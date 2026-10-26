# Released multi-architecture supplier; no Go rebuild or supplier rootfs copy.
FROM anchore/syft:v1.55.0-nonroot@sha256:ec5bdbc745485920c6f444239f0c09ed87b3c4c165ff9433f95bc66b3500fbf9 AS supplier

FROM cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde
COPY --from=supplier /syft /usr/local/bin/syft
ADD --chmod=0644 --checksum=sha256:c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4 https://raw.githubusercontent.com/anchore/syft/f15c3343e29dfb20cf6d82c820e7090b49808c96/LICENSE /usr/share/licenses/syft/LICENSE
# Embedded dependencies still require complete notices/SBOM review before publication.
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true
WORKDIR /tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/syft"]
