# Build-only Rust runner; no test runner/compiler enters the final image.
FROM cgr.dev/chainguard/rust:latest-dev@sha256:a39f7f8d82a307b5a766253bbc6b169e806086bbabc3ed257895ae90205f0ee3 AS unit-gate
USER 0
COPY --chmod=0444 src/scanner_units.rs /scanner_units.rs
RUN --network=none ["rustc", "--edition=2024", "-Dwarnings", "-Ctarget-feature=+crt-static", "/scanner_units.rs", "-o", "/scanner-units"]

# Fixed released source plus reviewed dependency patch; advisory data stays external.
FROM golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d AS sources
# Upstream tar.zst writer controls require the genuine compressor in the SDK.
RUN ["apt-get", "update"]
RUN ["apt-get", "install", "--no-install-recommends", "-y", "zstd"]
WORKDIR /src
RUN ["mkdir", "/out"]
RUN ["chown", "65532:65532", "/src", "/out"]
ENV HOME=/tmp GOPATH=/tmp/go GOCACHE=/tmp/go-build GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org CGO_ENABLED=0 GOMAXPROCS=4 GOFLAGS=-mod=readonly GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0
USER 65532:65532
ADD --chmod=0444 --checksum=sha256:3d2590a32fb09200d339ad410178ea2d0b1c550ab23743f29476a89c0fe193a5 https://codeload.github.com/anchore/grype/tar.gz/cd1f23eb50dfb52647090158f453c7359172591f /source.tar.gz
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
# Resolve the genuine vulnerable-symbol fixtures before offline regression tests.
RUN ["go", "-C", "grype/matcher/golang/testdata/gobin-xnet-http2server", "mod", "download", "all"]
RUN ["go", "-C", "grype/matcher/golang/testdata/gobin-xnet-html", "mod", "download", "all"]
RUN --network=none ["git", "restore", "--", "grype/matcher/golang/testdata/gobin-xnet-http2server/go.sum", "grype/matcher/golang/testdata/gobin-xnet-html/go.sum"]
COPY --from=unit-gate /scanner-units /scanner-units
# Actual scratch-only upstream package fixture, not a Docker socket fallback.
RUN --network=none ["mkdir", "-p", "/src/grype/pkg/testdata/cache"]
COPY --chown=65532:65532 tests/fixtures/grype-source-cache/image-simple.tar /src/grype/pkg/testdata/cache/stereoscope-fixture-image-simple-42ea0faabdf8f9815ba86da9e859efafbb1aef8cf6c6ecce9d62e26137b83880.tar
RUN --network=none ["chmod", "0755", "/src/grype/pkg/testdata/cache"]
# Cold compilation is separate from mandatory uncached race-test execution.
FROM sources AS unit-compiled
RUN --mount=type=cache,id=devsecops-grype-go1274-user,target=/tmp/go-build,uid=65532,gid=65532,mode=0700,sharing=locked --network=none ["env", "CGO_ENABLED=1", "GOPROXY=off", "/scanner-units", "grype", "compile"]
FROM unit-compiled AS unit-tested
RUN --mount=type=cache,id=devsecops-grype-go1274-user,target=/tmp/go-build,uid=65532,gid=65532,mode=0700,sharing=locked --network=none ["env", "CGO_ENABLED=1", "GOPROXY=off", "go", "test", "-race", "-count=1", "-p=1", "github.com/blakesmith/ar"]
RUN --mount=type=cache,id=devsecops-grype-go1274-user,target=/tmp/go-build,uid=65532,gid=65532,mode=0700,sharing=locked --network=none ["env", "CGO_ENABLED=1", "GOPROXY=off", "/scanner-units", "grype"]
FROM unit-tested AS supplier
RUN --mount=type=cache,id=devsecops-grype-go1274-user,target=/tmp/go-build,uid=65532,gid=65532,mode=0700,sharing=locked --network=none ["go", "build", "-tags=containers_image_openpgp,exclude_graphdriver_btrfs", "-ldflags=-w -s -extldflags '-static' -X main.version=0.121.3 -X main.gitCommit=cd1f23eb50dfb52647090158f453c7359172591f -X main.buildDate=unknown -X main.gitDescription=v0.121.3-dependency-security.1", "-o", "/out/grype", "./cmd/grype"]

FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
COPY --from=supplier /out/grype /usr/local/bin/grype
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
