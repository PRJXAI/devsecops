# Fixed released source plus reviewed dependency patch; advisory data stays external.
FROM golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d AS supplier
WORKDIR /src
ENV GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org CGO_ENABLED=0 GOMAXPROCS=4 GOFLAGS=-mod=readonly GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0
ADD --checksum=sha256:3d2590a32fb09200d339ad410178ea2d0b1c550ab23743f29476a89c0fe193a5 https://codeload.github.com/anchore/grype/tar.gz/cd1f23eb50dfb52647090158f453c7359172591f /source.tar.gz
RUN --network=none ["tar", "--no-same-owner", "-xzf", "/source.tar.gz", "--strip-components=1", "-C", "/src"]
RUN --network=none ["git", "init"]
RUN ["git", "fetch", "--depth=1", "https://github.com/anchore/grype.git", "cd1f23eb50dfb52647090158f453c7359172591f"]
RUN --network=none ["git", "reset", "--mixed", "cd1f23eb50dfb52647090158f453c7359172591f"]
RUN --network=none ["git", "diff", "--exit-code"]
COPY --chmod=0444 patches/grype-0.121.3-security.patch.txt /security.patch
RUN --network=none ["git", "apply", "--check", "/security.patch"]
RUN --network=none ["git", "apply", "/security.patch"]
RUN ["go", "mod", "download"]
RUN --network=none ["go", "mod", "verify"]
RUN --network=none ["env", "CGO_ENABLED=1", "GOPROXY=off", "go", "test", "-race", "-p=1", "github.com/blakesmith/ar"]
RUN --network=none ["env", "CGO_ENABLED=1", "GOPROXY=off", "go", "test", "-race", "-p=1", "-tags=containers_image_openpgp,exclude_graphdriver_btrfs", "./..."]
RUN --network=none ["go", "build", "-tags=containers_image_openpgp,exclude_graphdriver_btrfs", "-ldflags=-w -s -extldflags '-static' -X main.version=0.121.3 -X main.gitCommit=cd1f23eb50dfb52647090158f453c7359172591f -X main.buildDate=unknown -X main.gitDescription=v0.121.3-dependency-security.1", "-o", "/grype", "./cmd/grype"]

FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
COPY --from=supplier /grype /usr/local/bin/grype
ADD --chmod=0644 --checksum=sha256:c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4 https://raw.githubusercontent.com/anchore/grype/cd1f23eb50dfb52647090158f453c7359172591f/LICENSE /usr/share/licenses/grype/LICENSE
# Retrieve a fresh DB separately; mount it read-only for network-disabled analysis.
COPY --chmod=0444 licenses/scanners/grype-NOTICES.txt /usr/share/licenses/grype/THIRD-PARTY-NOTICES.txt
COPY --chmod=0444 licenses/scanners/STATIC-BASE-NOTICES.txt /usr/share/licenses/static-base/NOTICES.txt
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_DB_CACHE_DIR=/cache/grype
WORKDIR /tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/grype"]
