VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= ghcr.io/justereseau/loki-vl-proxy
ARCHES  := amd64 arm64
LDFLAGS := -s -w -X main.version=$(VERSION)
COMPOSE := docker compose -f deploy/compose/docker-compose.yml
# same versions as .github/workflows/ci.yml
GOLANGCI_LINT_VERSION := v2.15.0
ACTIONLINT_VERSION    := 1.7.12
ZIZMOR_VERSION        := 1.33.1

.PHONY: build dist test race bench lint e2e docker compose-up compose-down clean

# Binary for the local machine.
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/loki-vl-proxy ./cmd/loki-vl-proxy

# Release binaries: Linux only, amd64 and arm64 (dist/linux_<arch>/loki-vl-proxy).
dist:
	@for arch in $(ARCHES); do \
		echo "building linux/$$arch"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags="$(LDFLAGS)" \
			-o dist/linux_$$arch/loki-vl-proxy ./cmd/loki-vl-proxy || exit 1; \
	done

test:
	go test ./...

race:
	go test -race ./...

bench:
	go test -run XXX -bench . -benchmem ./internal/...

# golangci-lint, actionlint and zizmor, as in CI (needs Docker only).
lint:
	docker run --rm -v "$(CURDIR)":/app -w /app golangci/golangci-lint:$(GOLANGCI_LINT_VERSION) golangci-lint run ./...
	docker run --rm -v "$(CURDIR)":/repo -w /repo rhysd/actionlint:$(ACTIONLINT_VERSION) -color
	docker run --rm -v "$(CURDIR)":/repo -w /repo ghcr.io/zizmorcore/zizmor:$(ZIZMOR_VERSION) --offline .github/workflows

# Runs the Grafana / Logs Drilldown request set against a real VictoriaLogs.
e2e:
	LOKI_VL_PROXY_E2E_URL=$${LOKI_VL_PROXY_E2E_URL:-http://localhost:9428} go test -count=1 -run E2E -v ./internal/proxy/

# Multi-arch image from the dist/ binaries (add PUSH=1 to push).
docker: dist
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMAGE):$(VERSION) $(if $(PUSH),--push,) .

compose-up:
	$(COMPOSE) up -d --build

compose-down:
	$(COMPOSE) down -v

clean:
	rm -rf bin dist
