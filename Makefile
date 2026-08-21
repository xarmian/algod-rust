ALGOD_TOKEN := aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ALGOD_URL := http://localhost:4001
COMPOSE := docker compose -f docker/docker-compose.yml
COMPOSE_RUST := docker compose -f docker/docker-compose.localnet-rust.yml
COMPOSE_RELAY := docker compose -f docker/docker-compose.test-relay.yml
COMPOSE_MIXED := docker compose -f docker/docker-compose.mixed-cluster.yml
COMPOSE_VALIDATE_API := docker compose -f docker/docker-compose.validate-api.yml
PHASE6_CLUSTER := ops/mixed-cluster

.PHONY: build test fmt fmt-check clippy lint deny ci clean coverage coverage-lcov
.PHONY: validate-api-up validate-api-down validate-api-status validate-api-logs validate-api
.PHONY: replay-mainnet replay-testnet replay-stateful replay-mainnet-stateful replay-mainnet-1k
.PHONY: avm-replay avm-replay-mainnet
.PHONY: bench-rust bench-decode bench-go bench-micro bench-micro-go bench-cluster benchmark
.PHONY: archival-up archival-down
.PHONY: localnet-up localnet-down localnet-status localnet-logs algokey-e2e
.PHONY: localnet-rust-up localnet-rust-down localnet-rust-status localnet-rust-logs localnet-rust-genesis
.PHONY: capture validate validate-only generate-txns fixtures help
.PHONY: generate-diverse-txns fixtures-diverse
.PHONY: canonical-extract extract-trackerdb-fixtures
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

## Test/bench source files are excluded from coverage reports — they are
## scaffolding, not shipped code. Matches .github/workflows/coverage.yml and
## docs/COVERAGE.md. Requires cargo-llvm-cov (cargo install cargo-llvm-cov).
COVERAGE_IGNORE := (^|[/\\])(tests|benches)[/\\]

coverage:
	cargo llvm-cov --workspace --ignore-filename-regex '$(COVERAGE_IGNORE)' --open

coverage-lcov:
	cargo llvm-cov --workspace --ignore-filename-regex '$(COVERAGE_IGNORE)' --lcov --output-path lcov.info

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

## ── Localnet (Rust, Docker) ───────────────────────────────────
## Boots the Rust `algod-rust node start --dev` daemon in docker as a drop-in
## alternative to the `algod-go` localnet. Genesis (devmode + funded dev
## account) and config are baked into the image; dev mode produces a block per
## submitted transaction group, so a fresh `up` accepts transactions over REST
## (the image ships only the daemon — drive it from a host-side client on
## localhost:4001). See docs/DEV_WORKFLOW.md for the dev-account mnemonic.

## Regenerate the baked localnet genesis.json from genesis.json.in, deriving
## `proto` from the shared `CONSENSUS_CURRENT_VERSION` constant (BT-284) so the
## dev-only genesis tracks the project's current consensus version automatically.
localnet-rust-genesis:
	@bash docker/scripts/gen-localnet-genesis.sh

localnet-rust-up: localnet-rust-genesis
	$(COMPOSE_RUST) up -d --build algod-rust-localnet
	@echo "Waiting for algod-rust-localnet to be healthy..."
	@until docker inspect --format='{{.State.Health.Status}}' algod-rust-localnet 2>/dev/null | grep -q healthy; do \
		sleep 1; \
	done
	@echo "algod-rust-localnet is healthy — REST API on http://localhost:4001"

localnet-rust-down:
	$(COMPOSE_RUST) down -v

localnet-rust-status:
	@curl -s $(ALGOD_URL)/v2/status \
		-H "X-Algo-API-Token: $(ALGOD_TOKEN)" | python3 -m json.tool

localnet-rust-logs:
	$(COMPOSE_RUST) logs -f algod-rust-localnet

## algokey-rust end-to-end suite against a live algod-go localnet (PLAN-183 Phase D).
## Brings the localnet up, runs the smoke + keyreg + compat-matrix tests,
## and tears the localnet down even if the test suite fails.
##
## Prerequisites:
##   - docker + docker compose
##   - go-algorand@v4.5.1-stable `algokey` binary on PATH (compat matrix only;
##     missing binary causes the matrix tests to skip-with-notice rather than fail)
##
## `--test-threads=1` serializes the e2e test binaries so they don't race on
## the shared localnet's account/round state.
algokey-e2e:
	$(MAKE) localnet-up
	@echo "==> Running algokey-rust e2e suite..."
	@cargo test -p algokey-rust --features e2e -- --test-threads=1; \
	  STATUS=$$?; \
	  $(MAKE) localnet-down; \
	  exit $$STATUS

## ── Dual-node REST conformance harness (issue #129) ──────────
## Boots a real go-algorand v4.5.1-stable node (in Docker) and a real
## algod-rust node (run *natively*, not in Docker — see
## docker/docker-compose.validate-api.yml's header comment: building it a
## second time via `docker compose up --build` on top of the native
## `cargo test --release` build performs two full uncached release compiles
## and blows past CI's timeout) from the *same* baked genesis
## (docker/localnet-rust/data/) on distinct ports (go: 4001, rust: 4002), so
## live requests can be compared byte-for-byte, not just structurally.
## VALIDATE_API_RUST_DATA is a scratch copy of the tracked genesis fixtures
## the native process is free to write its ledger/tracker DBs into; it is
## rebuilt fresh on every `validate-api-up` and is not tracked by git.
##
## `validate-api-up` also pre-builds the live parity test binaries
## (--no-run) before starting the native algod-rust process: `cargo test`
## always uplifts every bin target of the package under test (so
## CARGO_BIN_EXE_* env vars are populated even if unused), which would
## otherwise try to overwrite target/release/algod-rust.exe while the
## harness process still has it open -- fatal on Windows (file locking;
## fine on Linux/CI, but pre-building keeps the sequencing safe everywhere).

VALIDATE_API_RUST_DATA := .validate-api-rust-data
VALIDATE_API_RUST_PID := .validate-api-rust.pid

validate-api-up:
	$(COMPOSE_VALIDATE_API) up -d
	@echo "Waiting for algod-go-shared to be healthy..."
	@until docker inspect --format='{{.State.Health.Status}}' algod-go-shared 2>/dev/null | grep -q healthy; do \
		sleep 1; \
	done
	@echo "==> Building algod-rust (release) and the live parity test binaries..."
	@cargo build --release --bin algod-rust
	@cargo test --release -p algod-rust --test live_go_parity --no-run
	@cargo test --release -p algod-rust --test live_msgpack_parity --no-run
	@cargo test --release -p algod-rust --test live_auth_parity --no-run
	@cargo test --release -p algod-rust --test live_txn_cross_verification --no-run
	@cargo test --release -p algod-rust --test live_longpoll_parity --no-run
	@echo "==> Starting algod-rust natively on :4002..."
	@rm -rf $(VALIDATE_API_RUST_DATA)
	@mkdir -p $(VALIDATE_API_RUST_DATA)
	@cp -r docker/localnet-rust/data/. $(VALIDATE_API_RUST_DATA)/
	@./target/release/algod-rust node start -d $(VALIDATE_API_RUST_DATA) --dev -l 0.0.0.0:4002 \
		>$(VALIDATE_API_RUST_DATA).log 2>&1 & echo $$! > $(VALIDATE_API_RUST_PID)
	@echo "Waiting for algod-rust to be healthy..."
	@until curl -sf -H "X-Algo-API-Token: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
		http://localhost:4002/v2/status >/dev/null 2>&1; do \
		sleep 1; \
	done
	@echo "Both nodes healthy — go on http://localhost:4001, rust on http://localhost:4002"

validate-api-down:
	$(COMPOSE_VALIDATE_API) down -v
	@if [ -f $(VALIDATE_API_RUST_PID) ]; then \
		kill $$(cat $(VALIDATE_API_RUST_PID)) 2>/dev/null || true; \
		rm -f $(VALIDATE_API_RUST_PID); \
	fi
	@rm -rf $(VALIDATE_API_RUST_DATA) $(VALIDATE_API_RUST_DATA).log

validate-api-status:
	@echo "== go ==" && curl -s http://localhost:4001/v2/status \
		-H "X-Algo-API-Token: $(ALGOD_TOKEN)" | python3 -m json.tool
	@echo "== rust ==" && curl -s http://localhost:4002/v2/status \
		-H "X-Algo-API-Token: $(ALGOD_TOKEN)" | python3 -m json.tool

validate-api-logs:
	$(COMPOSE_VALIDATE_API) logs -f

## Bring up the dual-node harness, run every live parity suite
## (bin/algod-rust/tests/live_go_parity.rs, live_msgpack_parity.rs,
## live_auth_parity.rs, live_txn_cross_verification.rs,
## live_longpoll_parity.rs), and tear down even if a suite fails — matching
## algokey-e2e's pattern. Reuses the same `target/release` build that
## validate-api-up already produced, so the harness process and the test
## binaries are never compiled twice.
##
## Order matters: live_go_parity, live_msgpack_parity, and live_auth_parity
## assume genesis-only state (round 0) or are otherwise read-only, so they
## run first, before live_txn_cross_verification and live_longpoll_parity
## submit any transactions and advance both nodes' rounds. Both of those also
## need --test-threads=1 (see each file's module docs) since their tests
## mutate the shared dev account's on-chain state. live_longpoll_parity's
## timeout test adds a real ~60s wait (go's WaitForBlockTimeout is a fixed
## 1-minute constant that can't be shortened without diverging from what's
## being verified — see that test's doc comment).
validate-api:
	$(MAKE) validate-api-up
	@echo "==> Running live dual-node parity suites..."
	@cargo test --release -p algod-rust --test live_go_parity -- --ignored --nocapture && \
	 cargo test --release -p algod-rust --test live_msgpack_parity -- --ignored --nocapture && \
	 cargo test --release -p algod-rust --test live_auth_parity -- --ignored --nocapture && \
	 cargo test --release -p algod-rust --test live_txn_cross_verification -- --ignored --nocapture --test-threads=1 && \
	 cargo test --release -p algod-rust --test live_longpoll_parity -- --ignored --nocapture --test-threads=1; \
	  STATUS=$$?; \
	  $(MAKE) validate-api-down; \
	  exit $$STATUS

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

## ── Trackerdb BLOB fixture capture (PLAN-36 G8 / TASK-119) ───
##
## Copies the Go-produced tracker SQLite out of the running localnet
## container and dumps every BLOB column as a hex fixture under
## `crates/core/algo-codec/tests/fixtures/trackerdb/<type>/`. Each
## type-subdirectory also gets a `_meta.json` recording provenance
## (go-algorand version, source data-dir prefix, capture timestamp,
## highest round seen).
##
## Prerequisites: localnet must have advanced far enough that the
## trackerdb tables are populated — `make fixtures-diverse` (default
## ~20 rounds) is sufficient for everything except `stateproof/`,
## which requires state-proof participation (typically ≥256 rounds
## with `EnableStateProof=true`).

# Algod container that ships the tracker DB (matches docker-compose service
# name in `docker/docker-compose.yml`).
TRACKERDB_CONTAINER ?= algod-go
# In-container path to the tracker file. Empty by default — the recipe
# autodiscovers it under `/algod/data` so the target keeps working
# regardless of which network-name subdir the algod docker image
# creates (devnet templates have varied between releases). Set this
# manually to pin a specific node when the container hosts more than
# one network.
TRACKERDB_CONTAINER_PATH ?=
# Local scratch directory. `make clean` does not touch it; remove
# manually after a regen run if you want to redo the export. Three
# files land here per capture: the main DB plus its `-wal` / `-shm`
# sidecars, so the SQLite reader sees a consistent view of any WAL
# frames the writer hasn't checkpointed yet.
TRACKERDB_LOCAL_DIR ?= /tmp/algod-rust-extract
TRACKERDB_LOCAL_COPY ?= $(TRACKERDB_LOCAL_DIR)/ledger.tracker.sqlite

extract-trackerdb-fixtures:
	@set -e; \
	SRC_PATH="$(TRACKERDB_CONTAINER_PATH)"; \
	if [ -z "$$SRC_PATH" ]; then \
		echo "==> Discovering tracker DB inside $(TRACKERDB_CONTAINER) ..."; \
		SRC_PATH=$$(docker exec $(TRACKERDB_CONTAINER) sh -c 'find /algod/data -maxdepth 4 -name ledger.tracker.sqlite 2>/dev/null | head -1'); \
		if [ -z "$$SRC_PATH" ]; then \
			echo "ERROR: ledger.tracker.sqlite not found under /algod/data in $(TRACKERDB_CONTAINER)."; \
			echo "       Override with 'make extract-trackerdb-fixtures TRACKERDB_CONTAINER_PATH=...'"; \
			exit 1; \
		fi; \
		echo "    found: $$SRC_PATH"; \
	fi; \
	mkdir -p $(TRACKERDB_LOCAL_DIR); \
	rm -f $(TRACKERDB_LOCAL_COPY) $(TRACKERDB_LOCAL_COPY)-wal $(TRACKERDB_LOCAL_COPY)-shm; \
	echo "==> Pausing $(TRACKERDB_CONTAINER) to take a consistent snapshot ..."; \
	docker pause $(TRACKERDB_CONTAINER) > /dev/null; \
	trap 'docker unpause $(TRACKERDB_CONTAINER) > /dev/null 2>&1 || true' EXIT; \
	echo "==> Copying tracker DB + WAL/SHM sidecars out of $(TRACKERDB_CONTAINER) ..."; \
	docker cp $(TRACKERDB_CONTAINER):$$SRC_PATH $(TRACKERDB_LOCAL_COPY); \
	docker cp $(TRACKERDB_CONTAINER):$$SRC_PATH-wal $(TRACKERDB_LOCAL_COPY)-wal 2>/dev/null || true; \
	docker cp $(TRACKERDB_CONTAINER):$$SRC_PATH-shm $(TRACKERDB_LOCAL_COPY)-shm 2>/dev/null || true; \
	echo "==> Resuming $(TRACKERDB_CONTAINER) ..."; \
	docker unpause $(TRACKERDB_CONTAINER) > /dev/null; \
	trap - EXIT; \
	echo "==> Dumping trackerdb BLOBs ..."; \
	cd docker/scripts/canonical-extract && go run . \
		-mode trackerdb-blobs \
		-tracker-db $(TRACKERDB_LOCAL_COPY) \
		-output-dir ../../../crates/core/algo-codec/tests/fixtures/trackerdb \
		-source-version $$(cd ../../../../go-algorand && git describe --always --dirty 2>/dev/null || echo unknown) \
		-source-prefix $$SRC_PATH
	@echo "==> Trackerdb BLOB fixtures regenerated under crates/core/algo-codec/tests/fixtures/trackerdb/"

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
	@echo "  make coverage         Workspace coverage, HTML report (cargo-llvm-cov)"
	@echo "  make coverage-lcov    Workspace coverage, lcov.info for editors/CI"
	@echo ""
	@echo "Localnet (Docker):"
	@echo "  make localnet-up      Start devnet (algod-go + txn-generator)"
	@echo "  make localnet-down    Stop devnet and remove volumes"
	@echo "  make localnet-status  Query node status"
	@echo "  make localnet-logs    Tail algod-go logs"
	@echo ""
	@echo "Localnet (Rust, Docker):"
	@echo "  make localnet-rust-up      Start Rust dev node (algod-rust node start --dev)"
	@echo "  make localnet-rust-down    Stop Rust dev node and remove volumes"
	@echo "  make localnet-rust-status  Query Rust node status (port 4001)"
	@echo "  make localnet-rust-logs    Tail algod-rust-localnet logs"
	@echo ""
	@echo "algokey-rust E2E:"
	@echo "  make algokey-e2e      Bring up localnet, run algokey-rust e2e suite (smoke +"
	@echo "                        keyreg + Go↔Rust compat matrix), tear down. Requires"
	@echo '                        go-algorand@v4.5.1-stable `algokey` on PATH for the'
	@echo "                        compat matrix (else skipped). PLAN-183."
	@echo ""
	@echo "Dual-Node REST Conformance (issue #129):"
	@echo "  make validate-api        Bring up go+rust on a shared genesis, run the"
	@echo "                           live parity suite, tear down (even on failure)"
	@echo "  make validate-api-up     Start both nodes (go:4001, rust:4002)"
	@echo "  make validate-api-down   Stop both nodes and remove volumes"
	@echo "  make validate-api-status Query /v2/status on both nodes"
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
	@echo "  make canonical-extract       Run Go tool to extract reference bytes"
	@echo "  make extract-trackerdb-fixtures"
	@echo "                              Dump trackerdb BLOBs as hex fixtures"
	@echo "                              (PLAN-36 G8; requires running localnet)"
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
