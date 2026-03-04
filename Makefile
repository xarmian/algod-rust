ALGOD_TOKEN := aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ALGOD_URL := http://localhost:4001
COMPOSE := docker compose -f docker/docker-compose.yml

.PHONY: build test fmt fmt-check clippy lint deny ci clean
.PHONY: localnet-up localnet-down localnet-status localnet-logs
.PHONY: capture validate validate-only generate-txns fixtures help

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

## ── Transaction Generation ───────────────────────────────────

N ?= 6

generate-txns:
	@FROM=$$(docker exec algod-go goal account list -d /algod/data 2>/dev/null | head -1 | awk '{print $$2}'); \
	TO=$$(docker exec algod-go goal account list -d /algod/data 2>/dev/null | tail -1 | awk '{print $$2}'); \
	if [ -z "$$FROM" ] || [ -z "$$TO" ]; then \
		echo "ERROR: Could not discover accounts. Is localnet running?"; exit 1; \
	fi; \
	echo "Sending $(N) transactions ($$FROM -> $$TO)..."; \
	for i in $$(seq 1 $(N)); do \
		docker exec algod-go goal clerk send -a 1000 \
			-f "$$FROM" -t "$$TO" \
			-d /algod/data -n "make-txn-$$i" || exit 1; \
	done; \
	echo "$(N) transactions sent."

## ── Fixture Pipeline ────────────────────────────────────────

FIXTURE_BLOCKS ?= 5

fixtures: localnet-up
	@echo "==> Generating $(shell echo $$(($(FIXTURE_BLOCKS)+1))) transactions ($(FIXTURE_BLOCKS) blocks + 1 for digest)..."
	$(MAKE) generate-txns N=$(shell echo $$(($(FIXTURE_BLOCKS)+1)))
	@echo "==> Capturing blocks 1-$(FIXTURE_BLOCKS)..."
	cargo run --bin algod-rust -- capture \
		--algod-url $(ALGOD_URL) --algod-token $(ALGOD_TOKEN) \
		--start 1 --end $(FIXTURE_BLOCKS) --out ./fixtures
	@echo "==> Copying fixtures to test directory..."
	@mkdir -p crates/core/algo-codec/tests/fixtures
	@for i in $$(seq 1 $(FIXTURE_BLOCKS)); do \
		cp fixtures/block_$$i.msgpack crates/core/algo-codec/tests/fixtures/; \
	done
	@echo "==> Extracting Go canonical references..."
	$(MAKE) canonical-extract
	@echo "==> Fixtures regenerated successfully."

## ── Canonical Reference Extraction ───────────────────────────

canonical-extract:
	cd docker/scripts/canonical-extract && go run . \
		-algod-url $(ALGOD_URL) \
		-algod-token $(ALGOD_TOKEN) \
		-output-dir ../../../crates/core/algo-codec/tests/fixtures/canonical

## ── Conformance Tools ─────────────────────────────────────────

VALIDATE_BLOCKS ?= 5

capture:
	cargo run --bin algod-rust -- capture \
		--algod-url $(ALGOD_URL) \
		--algod-token $(ALGOD_TOKEN) \
		--start 1 --end $(FIXTURE_BLOCKS)

validate: build localnet-up
	@echo "==> Generating $(VALIDATE_BLOCKS) transactions..."
	$(MAKE) generate-txns N=$(VALIDATE_BLOCKS)
	@echo "==> Running conformance validation (rounds 1-$(VALIDATE_BLOCKS))..."
	cargo run --bin algod-rust -- validate \
		--algod-url $(ALGOD_URL) \
		--algod-token $(ALGOD_TOKEN) \
		--start 1 --end $(VALIDATE_BLOCKS) \
		--report ./reports/conformance.json
	@echo "==> Report written to ./reports/conformance.json"

validate-only:
	cargo run --bin algod-rust -- validate \
		--algod-url $(ALGOD_URL) \
		--algod-token $(ALGOD_TOKEN) \
		--report ./reports/conformance.json

## ── Help ─────────────────────────────────────────────────────

help:
	@echo "algod-rust — Algorand Rust conformance tools"
	@echo ""
	@echo "Build & Test:"
	@echo "  make build            Build all crates"
	@echo "  make test             Run all tests (needs fixtures)"
	@echo "  make lint             Run fmt-check + clippy"
	@echo "  make ci               Run lint + test"
	@echo ""
	@echo "Localnet (Docker):"
	@echo "  make localnet-up      Start devnet (algod-go + txn-generator)"
	@echo "  make localnet-down    Stop devnet and remove volumes"
	@echo "  make localnet-status  Query node status"
	@echo "  make localnet-logs    Tail algod-go logs"
	@echo ""
	@echo "Transaction Generation:"
	@echo "  make generate-txns    Send N test transactions (default N=6)"
	@echo ""
	@echo "Fixtures:"
	@echo "  make fixtures         Full fixture regeneration pipeline"
	@echo "                        (localnet-up + txns + capture + extract)"
	@echo "  make capture          Capture block fixtures from algod"
	@echo "  make canonical-extract  Run Go tool to extract reference bytes"
	@echo ""
	@echo "Conformance:"
	@echo "  make validate         End-to-end: build + localnet + txns + validate"
	@echo "                        (writes ./reports/conformance.json)"
	@echo "  make validate-only    Validate against already-running localnet"
