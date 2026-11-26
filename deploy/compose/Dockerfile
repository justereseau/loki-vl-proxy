# syntax=docker/dockerfile:1
#
# Builds the proxy from source, for the local docker-compose stack.
# Release images are built from the pipeline binaries (see /Dockerfile).
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/loki-vl-proxy ./cmd/loki-vl-proxy

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/loki-vl-proxy /loki-vl-proxy
EXPOSE 3100
USER 65532:65532
ENTRYPOINT ["/loki-vl-proxy"]
