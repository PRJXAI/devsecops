# Fixed-source compiler experiment only; not a production or publishing recipe.
FROM cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde
COPY --chmod=0555 candidate /usr/local/bin/syft
LABEL org.prjxai.experiment=syft-compiler
ENV HOME=/tmp XDG_CACHE_HOME=/tmp/.cache SYFT_CHECK_FOR_APP_UPDATE=false SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true
WORKDIR /tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/syft"]
