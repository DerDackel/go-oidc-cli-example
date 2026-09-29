BINARY := oidc-cli
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

COMPOSE := docker compose

.PHONY: build test vet fmt clean keycloak-up keycloak-down keycloak-logs

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/oidc-cli

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

clean:
	rm -f $(BINARY)

# Local OpenID Connect provider for the demo, see docker-compose.yml.
keycloak-up:
	$(COMPOSE) up -d --wait

keycloak-down:
	$(COMPOSE) down -v

keycloak-logs:
	$(COMPOSE) logs -f keycloak
