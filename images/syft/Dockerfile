# Fixed released source plus reviewed dependency patch; not an unmodified supplier binary.
FROM golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d AS supplier
WORKDIR /src
ENV GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org CGO_ENABLED=0 GOMAXPROCS=4 GOFLAGS=-mod=readonly GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0
ADD --checksum=sha256:471041a3989580b912bae1675e92a71807ccc64b2cbabdbaf3e5586fa7b395e8 https://codeload.github.com/anchore/syft/tar.gz/a0c0d3890a9d79421c403e8fcadec50a2e55bf21 /source.tar.gz
RUN --network=none ["tar", "--no-same-owner", "-xzf", "/source.tar.gz", "--strip-components=1", "-C", "/src"]
# Restore authentic upstream Git identity required by upstream tests/build metadata.
RUN --network=none ["git", "init"]
RUN ["git", "fetch", "--depth=1", "https://github.com/anchore/syft.git", "a0c0d3890a9d79421c403e8fcadec50a2e55bf21"]
RUN --network=none ["git", "reset", "--mixed", "a0c0d3890a9d79421c403e8fcadec50a2e55bf21"]
RUN --network=none ["git", "diff", "--exit-code"]
COPY --chmod=0444 patches/syft-1.57.1-security.patch.txt /security.patch
RUN --network=none ["git", "apply", "--check", "/security.patch"]
RUN --network=none ["git", "apply", "/security.patch"]
RUN ["go", "mod", "download"]
RUN --network=none ["go", "mod", "verify"]
# Includes the fork's negative-member-size regression, not only Syft's own tests.
RUN --network=none ["env", "CGO_ENABLED=1", "GOPROXY=off", "go", "test", "-race", "-p=1", "github.com/blakesmith/ar"]
RUN --network=none ["env", "CGO_ENABLED=1", "GOPROXY=off", "go", "test", "-race", "-p=1", "-tags=containers_image_openpgp,exclude_graphdriver_btrfs", "./..."]
RUN --network=none ["go", "build", "-tags=containers_image_openpgp,exclude_graphdriver_btrfs", "-ldflags=-w -s -extldflags '-static' -X main.version=1.57.1 -X main.gitCommit=a0c0d3890a9d79421c403e8fcadec50a2e55bf21 -X main.buildDate=unknown -X main.gitDescription=v1.57.1-dependency-security.1", "-o", "/syft", "./cmd/syft"]

FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
COPY --from=supplier /syft /usr/local/bin/syft
ADD --chmod=0644 --checksum=sha256:c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4 https://raw.githubusercontent.com/anchore/syft/a0c0d3890a9d79421c403e8fcadec50a2e55bf21/LICENSE /usr/share/licenses/syft/LICENSE
COPY --chmod=0444 licenses/scanners/syft-NOTICES.txt /usr/share/licenses/syft/THIRD-PARTY-NOTICES.txt
COPY --chmod=0444 licenses/scanners/STATIC-BASE-NOTICES.txt /usr/share/licenses/static-base/NOTICES.txt
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true
WORKDIR /tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/syft"]
