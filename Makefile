ALGOD_TOKEN := aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ALGOD_URL := http://localhost:4001
COMPOSE := docker compose -f docker/docker-compose.yml

.PHONY: build test fmt fmt-check clippy lint deny ci clean
.PHONY: replay-mainnet replay-testnet replay-stateful replay-mainnet-stateful replay-mainnet-1k
.PHONY: archival-up archival-down
.PHONY: localnet-up localnet-down localnet-status localnet-logs
.PHONY: capture validate validate-only generate-txns fixtures help
.PHONY: generate-diverse-txns fixtures-diverse

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

generate-diverse-txns:
	docker exec algod-go bash /scripts/generate-diverse-txns.sh

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

DIVERSE_FIXTURE_BLOCKS ?= 12

fixtures-diverse: localnet-up
	@echo "==> Generating diverse transactions (all types)..."
	$(MAKE) generate-diverse-txns
	@echo "==> Sending one extra txn for final block digest extraction..."
	@FROM=$$(docker exec algod-go goal account list -d /algod/data 2>/dev/null | head -1 | awk '{print $$2}'); \
	TO=$$(docker exec algod-go goal account list -d /algod/data 2>/dev/null | tail -1 | awk '{print $$2}'); \
	docker exec algod-go goal clerk send -a 1000 -f "$$FROM" -t "$$TO" -d /algod/data -n "digest-tail"
	@echo "==> Capturing blocks 1-$(DIVERSE_FIXTURE_BLOCKS)..."
	cargo run --bin algod-rust -- capture \
		--algod-url $(ALGOD_URL) --algod-token $(ALGOD_TOKEN) \
		--start 1 --end $(DIVERSE_FIXTURE_BLOCKS) --out ./fixtures
	@echo "==> Copying fixtures to test directory..."
	@mkdir -p crates/core/algo-codec/tests/fixtures
	@for i in $$(seq 1 $(DIVERSE_FIXTURE_BLOCKS)); do \
		cp fixtures/block_$$i.msgpack crates/core/algo-codec/tests/fixtures/; \
	done
	@echo "==> Extracting Go canonical references..."
	$(MAKE) canonical-extract CANONICAL_ROUNDS=1-$(DIVERSE_FIXTURE_BLOCKS)
	@echo "==> Diverse fixtures regenerated successfully."

## ── Canonical Reference Extraction ───────────────────────────

CANONICAL_ROUNDS ?= 1-5

canonical-extract:
	cd docker/scripts/canonical-extract && go run . \
		-algod-url $(ALGOD_URL) \
		-algod-token $(ALGOD_TOKEN) \
		-rounds $(CANONICAL_ROUNDS) \
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

## ── Replay (Mainnet / Testnet) ───────────────────────────────

REPLAY_START ?= 44000000
REPLAY_BLOCKS ?= 100
START_ROUND ?= 44000000
COUNT ?= 100

replay-mainnet:
	cargo run --release --bin algod-rust -- replay --network mainnet --start $(REPLAY_START) --end $$(( $(REPLAY_START) + $(REPLAY_BLOCKS) - 1 )) --report ./reports/mainnet-replay.json

replay-testnet:
	cargo run --release --bin algod-rust -- replay --network testnet --start $(REPLAY_START) --end $$(( $(REPLAY_START) + $(REPLAY_BLOCKS) - 1 )) --report ./reports/testnet-replay.json

replay-stateful: ## Run stateful replay against localnet
	cargo run --bin algod-rust -- replay \
		--stateful \
		--genesis docker/genesis/genesis.json \
		--network custom \
		--algod-url http://localhost:4001 \
		--algod-token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
		--start 1 \
		--end 100 \
		--db ./ledger-localnet.sqlite

replay-mainnet-1k: ## Run 1000-block stateful mainnet replay (no compare)
	cargo run --release --bin algod-rust -- replay \
		--stateful \
		--genesis crates/core/algo-ledger/tests/fixtures/mainnet-genesis.json \
		--network mainnet \
		--start $(START_ROUND) \
		--end $$(( $(START_ROUND) + 999 )) \
		--db ./ledger-mainnet-1k.sqlite

replay-mainnet-stateful: ## Run stateful replay against mainnet archival node
	cargo run --bin algod-rust -- replay \
		--stateful \
		--genesis crates/core/algo-ledger/tests/fixtures/mainnet-genesis.json \
		--network mainnet \
		--start $(START_ROUND) \
		--end $$(( $(START_ROUND) + $(COUNT) - 1 )) \
		--compare \
		--compare-url http://localhost:4002 \
		--compare-token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
		--db ./ledger-mainnet.sqlite

## ── Archival Node ───────────────────────────────────────────

archival-up: ## Start archival Go node
	docker compose -f docker/docker-compose.yml --profile archival up -d

archival-down: ## Stop archival Go node
	docker compose -f docker/docker-compose.yml --profile archival down

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
	@echo "  make generate-txns          Send N payment transactions (default N=6)"
	@echo "  make generate-diverse-txns  Send diverse txn types (pay/axfer/acfg/afrz/appl/keyreg)"
	@echo ""
	@echo "Fixtures:"
	@echo "  make fixtures               Full fixture regeneration (payments only)"
	@echo "                              (localnet-up + txns + capture + extract)"
	@echo "  make fixtures-diverse       Fixture regeneration with all txn types"
	@echo "                              (localnet-up + diverse txns + capture + extract)"
	@echo "  make capture          Capture block fixtures from algod"
	@echo "  make canonical-extract  Run Go tool to extract reference bytes"
	@echo ""
	@echo "Conformance:"
	@echo "  make validate         End-to-end: build + localnet + txns + validate"
	@echo "                        (writes ./reports/conformance.json)"
	@echo "  make validate-only    Validate against already-running localnet"
	@echo ""
	@echo "Stateful Replay:"
	@echo "  make replay-stateful           Stateful replay against localnet (rounds 1-100)"
	@echo "  make replay-mainnet-1k         1000-block stateful mainnet replay (no compare)"
	@echo "  make replay-mainnet-stateful   Stateful replay against mainnet archival node"
	@echo "                                 (START_ROUND=$(START_ROUND), COUNT=$(COUNT))"
	@echo ""
	@echo "Archival Node:"
	@echo "  make archival-up      Start archival Go node (docker)"
	@echo "  make archival-down    Stop archival Go node"
