# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
FROM docker:29.9.2-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb AS supplier
FROM cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde
LABEL org.opencontainers.image.source="https://github.com/PRJXAI/devsecops" \
      org.opencontainers.image.title="Docker CLI with Compose and Buildx" \
      org.opencontainers.image.version="29.9.2-compose5.6.1-buildx0.38.1"
COPY --from=supplier --chown=65532:65532 /usr/local/bin/docker /usr/local/bin/docker
COPY --from=supplier --chown=65532:65532 /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
COPY --from=supplier --chown=65532:65532 /usr/local/libexec/docker/cli-plugins/docker-buildx /usr/local/libexec/docker/cli-plugins/docker-buildx
# Top-level notices only; complete embedded-dependency notice review still blocks publication.
ADD --checksum=sha256:2d81ea060825006fc8f3fe28aa5dc0ffeb80faf325b612c955229157b8c10dc0 --chmod=0444 https://raw.githubusercontent.com/docker/cli/a82e528901260c8df6073311379eac65f92db204/LICENSE /usr/share/licenses/docker/LICENSE
ADD --checksum=sha256:a8c869fbda819afb8d80e0ac19bac52e766bc6c19cb38cf94f52d64c4be2aab6 --chmod=0444 https://raw.githubusercontent.com/docker/cli/a82e528901260c8df6073311379eac65f92db204/NOTICE /usr/share/licenses/docker/NOTICE
ADD --checksum=sha256:58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd --chmod=0444 https://raw.githubusercontent.com/docker/compose/6cbc19a3fd59e305fb814dca4d854a4fb67d2941/LICENSE /usr/share/licenses/compose/LICENSE
ADD --checksum=sha256:b7dca0a6b01fa7365e4892877a6321179ee343d72ee87a96cfc222141b99a1e6 --chmod=0444 https://raw.githubusercontent.com/docker/compose/6cbc19a3fd59e305fb814dca4d854a4fb67d2941/NOTICE /usr/share/licenses/compose/NOTICE
ADD --checksum=sha256:cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 --chmod=0444 https://raw.githubusercontent.com/docker/buildx/0dbe87f36ed472fe36b6796c3f70b4210a731fc5/LICENSE /usr/share/licenses/buildx/LICENSE
ENV HOME=/tmp
USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/docker"]
CMD ["--help"]
