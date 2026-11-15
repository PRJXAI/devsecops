# Build-only Rust runner: upstream unit scope, never a shipped tool payload.
FROM cgr.dev/chainguard/rust:latest-dev@sha256:a39f7f8d82a307b5a766253bbc6b169e806086bbabc3ed257895ae90205f0ee3 AS unit-gate
USER 0
COPY --chmod=0444 src/scanner_units.rs /scanner_units.rs
RUN --network=none ["rustc", "--edition=2024", "-Dwarnings", "-Ctarget-feature=+crt-static", "/scanner_units.rs", "-o", "/scanner-units"]

# Public upstream test data, immutable OCI content; no Docker socket is exposed.
FROM ghcr.io/oras-project/oras:v1.3.6@sha256:9cfb578be975b762fd898b9d004243d8003aeb807a3e15b2ed212cdd1326c9eb AS fixtures
USER 0
WORKDIR /cache
RUN ["/bin/oras", "pull", "ghcr.io/anchore/oss-cache/syft-test-fixture-cache@sha256:12e1cbf78a9834abc7cb750dc18355bdd85485f30b9f004d9f99b7eb32a6ea3c", "--output", "/cache"]

# Fixed released source plus reviewed dependency patch; not an unmodified supplier binary.
FROM golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d AS sources
# Permission-denial controls require non-root execution and genuine ZIP tools.
RUN ["apt-get", "update"]
RUN ["apt-get", "install", "--no-install-recommends", "-y", "zip"]
WORKDIR /src
RUN ["mkdir", "/out"]
RUN ["chown", "65532:65532", "/src", "/out"]
ENV HOME=/tmp GOPATH=/tmp/go GOCACHE=/tmp/go-build GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org CGO_ENABLED=0 GOMAXPROCS=4 GOFLAGS=-mod=readonly GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0
USER 65532:65532
ADD --chmod=0444 --checksum=sha256:471041a3989580b912bae1675e92a71807ccc64b2cbabdbaf3e5586fa7b395e8 https://codeload.github.com/anchore/syft/tar.gz/a0c0d3890a9d79421c403e8fcadec50a2e55bf21 /source.tar.gz
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
# Prefetch real Go-source fixture graphs, then restore their original manifests.
RUN ["go", "-C", "syft/pkg/cataloger/golang/testdata/go-source-replacements", "mod", "download", "all"]
RUN ["go", "-C", "syft/pkg/cataloger/golang/internal/gotestdata/go-source", "mod", "download", "all"]
RUN --network=none ["git", "restore", "--", "syft/pkg/cataloger/golang/testdata/go-source-replacements/go.sum", "syft/pkg/cataloger/golang/internal/gotestdata/go-source/go.sum"]
COPY --from=unit-gate /scanner-units /scanner-units
# Only the pinned fixture artifact's testdata trees and cache fingerprint, not a rootfs.
COPY --from=fixtures --chown=65532:65532 /cache/ /src/
# Actual scratch-image archives built from the pinned upstream OS fixtures.
RUN --network=none ["mkdir", "-p", "/src/internal/os/testdata/cache"]
COPY --chown=65532:65532 tests/fixtures/syft-os-cache/not-rhel.tar /src/internal/os/testdata/cache/stereoscope-fixture-not_rhel-72b2a46da2554908034dbcd3f6ffbf4c098c9377e5a58abf729ee9de8f42d2a0.tar
COPY --chown=65532:65532 tests/fixtures/syft-os-cache/rhel-manifests.tar /src/internal/os/testdata/cache/stereoscope-fixture-rhel_content_manifests-637e4cfac50d7b5122173d45aa8ac1ca7ff2c18b1994519f616b99da9c2f3d1f.tar
COPY --chown=65532:65532 tests/fixtures/syft-os-cache/rhel-no-manifests.tar /src/internal/os/testdata/cache/stereoscope-fixture-rhel_no_manifests-5982583e26ad8209fb50063d2083d7e7894bb069cae67e65be9e54f271c1c35c.tar
RUN --network=none ["chmod", "0755", "/src/internal/os/testdata/cache"]
# A separate bounded native phase must complete before linking the payload.
FROM sources AS unit-tested
# Includes the fork's negative-member-size regression, not only Syft's own tests.
RUN --mount=type=cache,id=devsecops-syft-go1274-user,target=/tmp/go-build,uid=65532,gid=65532,mode=0700,sharing=locked --network=none ["env", "CGO_ENABLED=1", "GOPROXY=off", "go", "test", "-race", "-count=1", "-p=1", "github.com/blakesmith/ar"]
RUN --mount=type=cache,id=devsecops-syft-go1274-user,target=/tmp/go-build,uid=65532,gid=65532,mode=0700,sharing=locked --network=none ["env", "CGO_ENABLED=1", "GOPROXY=off", "/scanner-units", "syft"]
FROM unit-tested AS supplier
RUN --mount=type=cache,id=devsecops-syft-go1274-user,target=/tmp/go-build,uid=65532,gid=65532,mode=0700,sharing=locked --network=none ["go", "build", "-tags=containers_image_openpgp,exclude_graphdriver_btrfs", "-ldflags=-w -s -extldflags '-static' -X main.version=1.57.1 -X main.gitCommit=a0c0d3890a9d79421c403e8fcadec50a2e55bf21 -X main.buildDate=unknown -X main.gitDescription=v1.57.1-dependency-security.1", "-o", "/out/syft", "./cmd/syft"]

FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
COPY --from=supplier /out/syft /usr/local/bin/syft
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
