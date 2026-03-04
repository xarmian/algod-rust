ALGOD_TOKEN := aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ALGOD_URL := http://localhost:4001
COMPOSE := docker compose -f docker/docker-compose.yml

.PHONY: build test fmt fmt-check clippy lint deny ci clean
.PHONY: localnet-up localnet-down localnet-status localnet-logs
.PHONY: capture validate

## ── Build & Test ──────────────────────────────────────────────

build:
	cargo build --workspace

test:
	cargo test --workspace

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

lint: fmt-check clippy

deny:
	cargo deny check

ci: lint test

clean:
	cargo clean

## ── Localnet (Docker) ─────────────────────────────────────────

localnet-up:
	$(COMPOSE) up -d algod-go
	@echo "Waiting for algod-go to be healthy..."
	@until docker inspect --format='{{.State.Health.Status}}' algod-go 2>/dev/null | grep -q healthy; do \
		sleep 1; \
	done
	@echo "algod-go is healthy."

localnet-down:
	$(COMPOSE) down -v

localnet-status:
	@curl -s $(ALGOD_URL)/v2/status \
		-H "X-Algo-API-Token: $(ALGOD_TOKEN)" | python3 -m json.tool

localnet-logs:
	$(COMPOSE) logs -f algod-go

## ── Conformance Tools ─────────────────────────────────────────

capture:
	cargo run --bin algod-rust -- capture \
		--algod-url $(ALGOD_URL) \
		--algod-token $(ALGOD_TOKEN)

validate:
	cargo run --bin algod-rust -- validate \
		--algod-url $(ALGOD_URL) \
		--algod-token $(ALGOD_TOKEN) \
		--report ./reports/conformance.json
