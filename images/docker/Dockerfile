# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
FROM docker:29.9.2-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb AS supplier
FROM cgr.dev/chainguard/static:latest@sha256:9e2306b457ff71ce370043dc68c7b52bb1e6622c1c6c6714edbed57496f3116e
LABEL org.opencontainers.image.source="https://github.com/PRJXAI/devsecops" \
      org.opencontainers.image.title="Docker CLI with Compose and Buildx" \
      org.opencontainers.image.version="29.9.2-compose5.6.1-buildx0.38.1"
COPY --from=supplier --chown=65532:65532 /usr/local/bin/docker /usr/local/bin/docker
COPY --from=supplier --chown=65532:65532 /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
COPY --from=supplier --chown=65532:65532 /usr/local/libexec/docker/cli-plugins/docker-buildx /usr/local/libexec/docker/cli-plugins/docker-buildx
ENV HOME=/tmp
USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/docker"]
CMD ["--help"]
