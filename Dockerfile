# syntax=docker/dockerfile:1
#
# Release image: packages the prebuilt static binaries produced by the
# pipeline (or `make dist`) as dist/linux_<arch>/loki-vl-proxy. No compiler
# runs here, so the multi-arch image (linux/amd64, linux/arm64) is built from
# exactly the binaries attached to the GitHub release.
#
# Build from source instead: deploy/compose/Dockerfile.
FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETARCH
COPY dist/linux_${TARGETARCH}/loki-vl-proxy /loki-vl-proxy
EXPOSE 3100
USER nonroot:nonroot
ENTRYPOINT ["/loki-vl-proxy"]
