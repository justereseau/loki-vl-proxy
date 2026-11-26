VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= ghcr.io/justereseau/loki-vl-proxy
COMPOSE := docker compose -f deploy/compose/docker-compose.yml

.PHONY: build test race bench lint e2e docker compose-up compose-down

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/loki-vl-proxy ./cmd/loki-vl-proxy

test:
	go test ./...

race:
	go test -race ./...

bench:
	go test -run XXX -bench . -benchmem ./internal/...

lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...

# Runs the Grafana / Logs Drilldown request set against a real VictoriaLogs.
e2e:
	LOKI_VL_PROXY_E2E_URL=$${LOKI_VL_PROXY_E2E_URL:-http://localhost:9428} go test -count=1 -run E2E -v ./internal/proxy/

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

compose-up:
	$(COMPOSE) up -d --build

compose-down:
	$(COMPOSE) down -v
