# syntax=docker/dockerfile:1
#
# Release image: packages the prebuilt static binaries produced by the
# pipeline (or `make dist`) as dist/linux_<arch>/loki-vl-proxy. Nothing is
# compiled or run here, so the multi-arch image (linux/amd64, linux/arm64) is
# built from exactly the binaries attached to the GitHub release.
#
# Build from source instead: deploy/compose/Dockerfile.

# CA certificates for HTTPS upstreams (architecture independent).
FROM --platform=$BUILDPLATFORM gcr.io/distroless/static-debian12:nonroot AS certs

FROM scratch
ARG TARGETARCH
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY dist/linux_${TARGETARCH}/loki-vl-proxy /loki-vl-proxy
EXPOSE 3100
# no /etc/passwd in scratch: numeric nonroot user (same IDs as distroless)
USER 65532:65532
ENTRYPOINT ["/loki-vl-proxy"]
