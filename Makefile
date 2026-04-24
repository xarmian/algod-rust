ALGOD_TOKEN := aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ALGOD_URL := http://localhost:4001
COMPOSE := docker compose -f docker/docker-compose.yml
COMPOSE_RELAY := docker compose -f docker/docker-compose.test-relay.yml
COMPOSE_MIXED := docker compose -f docker/docker-compose.mixed-cluster.yml
PHASE6_CLUSTER := ops/mixed-cluster

.PHONY: build test fmt fmt-check clippy lint deny ci clean
.PHONY: replay-mainnet replay-testnet replay-stateful replay-mainnet-stateful replay-mainnet-1k
.PHONY: avm-replay avm-replay-mainnet
.PHONY: bench-rust bench-decode bench-go bench-micro bench-micro-go bench-cluster benchmark
.PHONY: archival-up archival-down
.PHONY: localnet-up localnet-down localnet-status localnet-logs
.PHONY: capture validate validate-only generate-txns fixtures help
.PHONY: generate-diverse-txns fixtures-diverse
.PHONY: relay-up relay-down relay-test
.PHONY: mixed-cluster-up mixed-cluster-down mixed-cluster-smoke mixed-cluster-test mixed-cluster-conformance
.PHONY: phase6-cluster-up phase6-cluster-down phase6-cluster-status

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

## ── AVM Replay ──────────────────────────────────────────────

avm-replay: ## Run AVM execution replay against localnet
	cargo run --bin algod-rust -- replay \
		--stateful \
		--avm-execute \
		--genesis docker/genesis/genesis.json \
		--network custom \
		--algod-url http://localhost:4001 \
		--algod-token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
		--start 1 \
		--end 100 \
		--db ./ledger-avm-localnet.sqlite

avm-replay-mainnet: ## Run AVM execution replay against mainnet
	cargo run --release --bin algod-rust -- replay \
		--stateful \
		--avm-execute \
		--genesis crates/core/algo-ledger/tests/fixtures/mainnet-genesis.json \
		--network mainnet \
		--start $(START_ROUND) \
		--end $$(( $(START_ROUND) + $(COUNT) - 1 )) \
		--db ./ledger-avm-mainnet.sqlite

## ── Test Relay (WebSocket Integration) ──────────────────────

relay-up: ## Start test relay for WebSocket integration tests
	$(COMPOSE_RELAY) up -d
	@echo "Waiting for algod-relay to be healthy..."
	@until docker inspect --format='{{.State.Health.Status}}' algod-relay 2>/dev/null | grep -q healthy; do \
		sleep 1; \
	done
	@echo "algod-relay is healthy — gossip on :4161, REST on :4003"

relay-down: ## Stop test relay and remove volumes
	$(COMPOSE_RELAY) down -v

relay-test: relay-up ## Run WebSocket integration tests against relay
	ALGO_RELAY_ADDR=localhost:4161 ALGO_RELAY_REST=http://localhost:4003 \
		cargo test -p algo-network --test ws_integration -- --nocapture
	$(MAKE) relay-down

## ── Mixed Cluster (Conformance Testing) ─────────────────────

mixed-cluster-up: ## Start mixed cluster (Go relay + Rust observer/relay + Go non-relay)
	$(COMPOSE_MIXED) build
	$(COMPOSE_MIXED) up -d go-relay
	@echo "Waiting for go-relay to be healthy..."
	@until docker inspect --format='{{.State.Health.Status}}' mc-go-relay 2>/dev/null | grep -q healthy; do \
		sleep 1; \
	done
	@echo "go-relay is healthy. Starting remaining services..."
	$(COMPOSE_MIXED) up -d
	@echo "Mixed cluster is up."
	@echo "Starting background transaction generator..."
	@$(MAKE) mixed-cluster-txns &

mixed-cluster-txns: ## Send periodic transactions to go-relay (runs in foreground)
	@echo "Discovering accounts..."
	@ACCOUNTS=$$(docker exec mc-go-relay goal account list -d /algod/data 2>/dev/null | awk '{print $$2}'); \
	FROM=$$(echo "$$ACCOUNTS" | head -1); \
	TO=$$(echo "$$ACCOUNTS" | tail -1); \
	if [ -z "$$FROM" ] || [ -z "$$TO" ]; then echo "ERROR: no accounts found"; exit 1; fi; \
	echo "Sending txns: $$FROM -> $$TO"; \
	SEQ=0; \
	while docker inspect --format='{{.State.Status}}' mc-go-relay 2>/dev/null | grep -q running; do \
		SEQ=$$((SEQ + 1)); \
		docker exec mc-go-relay goal clerk send -a 1000 -f "$$FROM" -t "$$TO" -d /algod/data -n "mc-txn-$$SEQ" >/dev/null 2>&1 || true; \
		sleep 5; \
	done; \
	echo "Transaction generator stopped (go-relay not running)."

mixed-cluster-down: ## Stop mixed cluster and remove volumes
	$(COMPOSE_MIXED) down -v

mixed-cluster-smoke: ## Quick connectivity check on the mixed cluster
	@echo "==> Checking go-relay REST..."
	@curl -sf -H "X-Algo-API-Token: $(ALGOD_TOKEN)" http://localhost:4001/v2/status | python3 -c "import sys,json; s=json.load(sys.stdin); print('  go-relay: round', s.get('last-round', '?'))"
	@echo "==> Checking rust-observer container is running..."
	@docker inspect --format='{{.State.Status}}' mc-rust-observer 2>/dev/null || echo "  rust-observer: NOT RUNNING"
	@echo "==> Checking rust-relay container is running..."
	@docker inspect --format='{{.State.Status}}' mc-rust-relay 2>/dev/null || echo "  rust-relay: NOT RUNNING"
	@echo "==> Checking go-nonrelay REST..."
	@curl -sf -H "X-Algo-API-Token: $(ALGOD_TOKEN)" http://localhost:4002/v2/status | python3 -c "import sys,json; s=json.load(sys.stdin); print('  go-nonrelay: round', s.get('last-round', '?'))" || echo "  go-nonrelay: NOT RESPONDING"
	@echo "==> Smoke check complete."

mixed-cluster-test: mixed-cluster-up ## Run full mixed-cluster conformance test
	@echo "==> Waiting for cluster to produce blocks..."
	@sleep 15
	@echo "==> Running smoke check..."
	$(MAKE) mixed-cluster-smoke
	@echo "==> Running cargo integration tests..."
	MIXED_CLUSTER=1 cargo test -p algo-network \
		--test mixed_cluster_connectivity \
		--test mixed_cluster_block_service \
		-- --ignored --nocapture
	@echo "==> Checking container logs for errors..."
	@echo "--- rust-observer (last 20 lines) ---"
	@docker logs mc-rust-observer --tail 20 2>&1 || true
	@echo "--- rust-relay (last 20 lines) ---"
	@docker logs mc-rust-relay --tail 20 2>&1 || true
	@echo "--- go-nonrelay (last 20 lines) ---"
	@docker logs mc-go-nonrelay --tail 20 2>&1 || true
	@echo "==> Mixed cluster test complete."
	$(MAKE) mixed-cluster-down

mixed-cluster-conformance: mixed-cluster-up ## Run long-running conformance tests (1000+ rounds, ~10 min)
	@echo "==> Waiting for cluster to produce blocks..."
	@sleep 15
	@echo "==> Running smoke check..."
	$(MAKE) mixed-cluster-smoke
	@echo "==> Running long-running conformance tests (this may take 10+ minutes)..."
	MIXED_CLUSTER=1 cargo test -p algo-network \
		--test mixed_cluster_conformance \
		-- --ignored --nocapture
	@echo "==> Checking container logs for errors..."
	@echo "--- rust-observer (last 20 lines) ---"
	@docker logs mc-rust-observer --tail 20 2>&1 || true
	@echo "--- rust-relay (last 20 lines) ---"
	@docker logs mc-rust-relay --tail 20 2>&1 || true
	@echo "--- go-nonrelay (last 20 lines) ---"
	@docker logs mc-go-nonrelay --tail 20 2>&1 || true
	@echo "==> Mixed cluster conformance test complete."
	$(MAKE) mixed-cluster-down

## ── Phase 6 mixed-cluster consensus harness (TASK-86) ──────────
phase6-cluster-up: ## Bring up the PLAN-32 4-node (3 Go + 1 Rust) consensus harness
	$(PHASE6_CLUSTER)/scripts/start.sh

phase6-cluster-status: ## Per-node round + peer-count snapshot for the phase6 cluster
	$(PHASE6_CLUSTER)/scripts/status.sh

phase6-cluster-down: ## Tear down the phase6 cluster (pass PURGE=1 to wipe netroot/)
	@if [ "$(PURGE)" = "1" ]; then \
		$(PHASE6_CLUSTER)/scripts/stop.sh --purge; \
	else \
		$(PHASE6_CLUSTER)/scripts/stop.sh; \
	fi

## ── Benchmarks ─────────────────────────────────────────────
BENCH_START  ?= 40000000
BENCH_COUNT  ?= 100
BENCH_OUTPUT ?= bench-results

bench-rust: ## Run Rust validated replay benchmark (end-to-end, includes network fetch)
	@mkdir -p $(BENCH_OUTPUT)
	cargo run --release --bin algod-rust -- bench replay \
		--start-round $(BENCH_START) --count $(BENCH_COUNT) \
		--output $(BENCH_OUTPUT)/bench-replay-rust.json

bench-decode: ## Run Rust decode-only benchmark (end-to-end, includes network fetch)
	@mkdir -p $(BENCH_OUTPUT)
	cargo run --release --bin algod-rust -- bench decode \
		--start-round $(BENCH_START) --count $(BENCH_COUNT) \
		--output $(BENCH_OUTPUT)/bench-decode-rust.json

bench-go: ## Run Go REST fetch benchmark (HTTP only, not for Go-vs-Rust comparison)
	@mkdir -p $(BENCH_OUTPUT)
	bash docker/scripts/bench-go.sh \
		--start-round $(BENCH_START) --count $(BENCH_COUNT) \
		--output $(BENCH_OUTPUT)/bench-replay-go.json

bench-micro: ## Run Rust criterion microbenchmarks
	cargo bench --workspace

bench-micro-go: ## Run Go decode microbenchmarks (same fixture files as Rust criterion)
	cd benchmarks/go-decode && go test -bench=. -benchmem -count=5

bench-cluster: ## Run mixed-cluster Go vs Rust comparison (requires Docker)
	bash docker/scripts/bench-cluster.sh

benchmark: bench-micro bench-micro-go ## Run all microbenchmarks (Rust + Go)
	@echo "Benchmark complete. For cluster comparison: make bench-cluster"

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
	@echo "AVM Replay:"
	@echo "  make avm-replay                AVM execution replay against localnet (rounds 1-100)"
	@echo "  make avm-replay-mainnet        AVM execution replay against mainnet"
	@echo "                                 (START_ROUND=$(START_ROUND), COUNT=$(COUNT))"
	@echo ""
	@echo "Test Relay (WebSocket):"
	@echo "  make relay-up         Start test relay (gossip on :4161)"
	@echo "  make relay-down       Stop test relay"
	@echo "  make relay-test       Start relay + run integration tests + stop relay"
	@echo ""
	@echo "Mixed Cluster (Conformance):"
	@echo "  make mixed-cluster-up     Start mixed cluster (Go relay + Rust + Go non-relay)"
	@echo "  make mixed-cluster-down   Stop mixed cluster and remove volumes"
	@echo "  make mixed-cluster-smoke  Quick connectivity check"
	@echo "  make mixed-cluster-test   Full conformance test (up + smoke + logs + down)"
	@echo ""
	@echo "Phase 6 Mixed-Cluster Consensus (TASK-86):"
	@echo "  make phase6-cluster-up      Bring up 4-node cluster (3 Go + 1 Rust)"
	@echo "  make phase6-cluster-status  Per-node round + liveness snapshot"
	@echo "  make phase6-cluster-down    Tear down (append PURGE=1 to wipe netroot/)"
	@echo ""
	@echo "Benchmarks (fair comparison):"
	@echo "  make bench-micro      Run Rust criterion microbenchmarks (fixture-based)"
	@echo "  make bench-micro-go   Run Go decode microbenchmarks (same fixture files)"
	@echo "  make bench-cluster    Run mixed-cluster Go vs Rust comparison (Docker)"
	@echo "  make benchmark        Run all microbenchmarks (Rust + Go)"
	@echo ""
	@echo "Benchmarks (single-implementation profiling):"
	@echo "  make bench-rust       Rust validated replay (includes HTTP fetch)"
	@echo "  make bench-decode     Rust decode-only (includes HTTP fetch)"
	@echo "  make bench-go         Go REST fetch (HTTP only, curl-based)"
	@echo "                        (BENCH_START=$(BENCH_START), BENCH_COUNT=$(BENCH_COUNT))"
	@echo ""
	@echo "Archival Node:"
	@echo "  make archival-up      Start archival Go node (docker)"
	@echo "  make archival-down    Stop archival Go node"
