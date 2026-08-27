ALGOD_TOKEN := aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ALGOD_URL := http://localhost:4001
COMPOSE := docker compose -f docker/docker-compose.yml
COMPOSE_RUST := docker compose -f docker/docker-compose.localnet-rust.yml
COMPOSE_RELAY := docker compose -f docker/docker-compose.test-relay.yml
COMPOSE_MIXED := docker compose -f docker/docker-compose.mixed-cluster.yml
COMPOSE_VALIDATE_API := docker compose -f docker/docker-compose.validate-api.yml
COMPOSE_VFUTURE := docker compose -f docker/docker-compose.vfuture.yml
PHASE6_CLUSTER := ops/mixed-cluster
PHASE7_CLUSTER := ops/mixed-cluster-3rust
P2P_INTEROP_CLUSTER := ops/mixed-cluster-p2p

.PHONY: build test fmt fmt-check clippy lint deny ci clean coverage coverage-lcov
.PHONY: validate-api-up validate-api-down validate-api-status validate-api-logs validate-api
.PHONY: replay-mainnet replay-testnet replay-stateful replay-mainnet-stateful replay-mainnet-1k
.PHONY: avm-replay avm-replay-mainnet
.PHONY: bench-rust bench-decode bench-go bench-micro bench-micro-go bench-cluster benchmark
.PHONY: bench-stress bench-stress-down
.PHONY: archival-up archival-down
.PHONY: localnet-up localnet-down localnet-status localnet-logs algokey-e2e
.PHONY: localnet-rust-up localnet-rust-down localnet-rust-status localnet-rust-logs localnet-rust-genesis
.PHONY: capture validate validate-only generate-txns fixtures help
.PHONY: vfuture-up vfuture-down vfuture-status vfuture-fixtures
.PHONY: generate-diverse-txns fixtures-diverse
.PHONY: canonical-extract extract-trackerdb-fixtures
.PHONY: relay-up relay-down relay-test
.PHONY: mixed-cluster-up mixed-cluster-down mixed-cluster-smoke mixed-cluster-test mixed-cluster-conformance
.PHONY: consensus-cluster-up consensus-cluster-down consensus-cluster-status consensus-cluster-smoke
.PHONY: consensus-cluster-test consensus-cluster-restart consensus-cluster-negative
.PHONY: consensus-cluster-analyzer
.PHONY: p2p-interop-up p2p-interop-down p2p-interop-test p2p-interop-status
.PHONY: p2p-interop-consensus-test p2p-interop-soak p2p-interop-soak-test
.PHONY: p2p-interop-verify p2p-interop-restart p2p-interop-negative
.PHONY: phase6-cluster-up phase6-cluster-down phase6-cluster-status
.PHONY: consensus-analyzer-test consensus-negative-test

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
##   - go-algorand@v4.7.3-stable `algokey` binary on PATH (compat matrix only;
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
## Boots a real go-algorand v4.7.3-stable node (in Docker) and a real
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

## Issue #612: a THIRD native algod-rust process that actually *syncs* from
## algod-go-shared (port 4001) over REST via `node start --follow` (see
## `bin/algod-rust/src/commands/node.rs`), instead of self-producing blocks
## like the `--dev` process on :4002 does. This is what lets
## `live_state_delta_parity.rs` diff `GET /v2/deltas/{round}` against a
## block that genuinely went through `SqliteLedger::apply_block_caching_delta`
## (the real sync path `commands/sync.rs` uses) rather than dev-mode's
## `cache_state_delta`-direct shortcut. Uses the same shared genesis as the
## other two nodes/services (see this file's own header comment) so its
## ledger state lines up with algod-go-shared's from round 0.
VALIDATE_API_RUST_SYNC_DATA := .validate-api-rust-sync-data
VALIDATE_API_RUST_SYNC_PID := .validate-api-rust-sync.pid

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
	@cargo test --release -p algod-rust --test live_headers_parity --no-run
	@cargo test --release -p algod-rust --test live_endpoint_sweep --no-run
	@cargo test --release -p algod-rust --test live_txn_cross_verification --no-run
	@cargo test --release -p algod-rust --test live_box_pagination_parity --no-run
	@cargo test --release -p algod-rust --test live_state_delta_parity --no-run
	@cargo test --release -p algod-rust --test live_longpoll_parity --no-run
	@cargo test --release -p algod-rust --test live_online_circulation_expiry --no-run
	@echo "==> Starting algod-rust natively on :4002..."
	@rm -rf $(VALIDATE_API_RUST_DATA)
	@mkdir -p $(VALIDATE_API_RUST_DATA)
	@cp -r docker/localnet-rust/data/. $(VALIDATE_API_RUST_DATA)/
	@printf '%s' "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" > $(VALIDATE_API_RUST_DATA)/algod.admin.token
	@./target/release/algod-rust node start -d $(VALIDATE_API_RUST_DATA) --dev -l 0.0.0.0:4002 \
		>$(VALIDATE_API_RUST_DATA).log 2>&1 & echo $$! > $(VALIDATE_API_RUST_PID)
	@echo "Waiting for algod-rust to be healthy..."
	@until curl -sf -H "X-Algo-API-Token: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
		http://localhost:4002/v2/status >/dev/null 2>&1; do \
		sleep 1; \
	done
	@echo "==> Starting algod-rust (--follow, issue #612 sync-path harness) natively on :4003..."
	@rm -rf $(VALIDATE_API_RUST_SYNC_DATA)
	@mkdir -p $(VALIDATE_API_RUST_SYNC_DATA)
	@cp -r docker/localnet-rust/data/. $(VALIDATE_API_RUST_SYNC_DATA)/
	@printf '%s' "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" > $(VALIDATE_API_RUST_SYNC_DATA)/algod.admin.token
	@./target/release/algod-rust node start -d $(VALIDATE_API_RUST_SYNC_DATA) \
		--follow http://localhost:4001 --follow-token $(ALGOD_TOKEN) -l 0.0.0.0:4003 \
		>$(VALIDATE_API_RUST_SYNC_DATA).log 2>&1 & echo $$! > $(VALIDATE_API_RUST_SYNC_PID)
	@echo "Waiting for algod-rust (sync) to be healthy..."
	@until curl -sf -H "X-Algo-API-Token: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
		http://localhost:4003/v2/status >/dev/null 2>&1; do \
		sleep 1; \
	done
	@echo "All three nodes healthy — go on http://localhost:4001, rust (--dev) on http://localhost:4002, rust (--follow, syncing from go) on http://localhost:4003"

validate-api-down:
	$(COMPOSE_VALIDATE_API) down -v
	@if [ -f $(VALIDATE_API_RUST_PID) ]; then \
		kill $$(cat $(VALIDATE_API_RUST_PID)) 2>/dev/null || true; \
		rm -f $(VALIDATE_API_RUST_PID); \
	fi
	@if [ -f $(VALIDATE_API_RUST_SYNC_PID) ]; then \
		kill $$(cat $(VALIDATE_API_RUST_SYNC_PID)) 2>/dev/null || true; \
		rm -f $(VALIDATE_API_RUST_SYNC_PID); \
	fi
	@rm -rf $(VALIDATE_API_RUST_DATA) $(VALIDATE_API_RUST_DATA).log
	@rm -rf $(VALIDATE_API_RUST_SYNC_DATA) $(VALIDATE_API_RUST_SYNC_DATA).log

validate-api-status:
	@echo "== go ==" && curl -s http://localhost:4001/v2/status \
		-H "X-Algo-API-Token: $(ALGOD_TOKEN)" | python3 -m json.tool
	@echo "== rust (--dev) ==" && curl -s http://localhost:4002/v2/status \
		-H "X-Algo-API-Token: $(ALGOD_TOKEN)" | python3 -m json.tool
	@echo "== rust (--follow) ==" && curl -s http://localhost:4003/v2/status \
		-H "X-Algo-API-Token: $(ALGOD_TOKEN)" | python3 -m json.tool

validate-api-logs:
	$(COMPOSE_VALIDATE_API) logs -f

## Bring up the dual-node harness, run every live parity suite
## (bin/algod-rust/tests/live_go_parity.rs, live_msgpack_parity.rs,
## live_auth_parity.rs, live_headers_parity.rs, live_endpoint_sweep.rs,
## live_txn_cross_verification.rs, live_box_pagination_parity.rs,
## live_longpoll_parity.rs, live_online_circulation_expiry.rs), and tear
## down even if a suite fails — matching algokey-e2e's pattern. Reuses the
## same `target/release` build that validate-api-up already produced, so
## the harness process and the test binaries are never compiled twice.
##
## Order matters: live_go_parity, live_msgpack_parity, live_auth_parity,
## live_headers_parity, and live_endpoint_sweep assume genesis-only state
## (round 0) or are otherwise read-only, so they run first, before
## live_txn_cross_verification, live_box_pagination_parity,
## live_longpoll_parity, and live_online_circulation_expiry submit
## transactions and advance both nodes' rounds. live_box_pagination_parity
## (issue #551) runs right after live_txn_cross_verification since it also
## deploys apps/submits transactions on the shared dev account and needs
## --test-threads=1 for the same reason (see each file's module docs).
## live_longpoll_parity's timeout test adds a real ~60s wait (go's
## WaitForBlockTimeout is a fixed 1-minute constant that can't be shortened
## without diverging from what's being verified — see that test's doc
## comment). live_online_circulation_expiry runs last since it's the
## heaviest (issue #518: it advances each node ~330 rounds via sequential
## filler transactions to cross MaxBalLookback, ~1-2 minutes per node) and,
## unlike the others, doesn't assume anything about the round it starts
## from.
validate-api:
	$(MAKE) validate-api-up
	@echo "==> Running live dual-node parity suites..."
	@cargo test --release -p algod-rust --test live_go_parity -- --ignored --nocapture && \
	 cargo test --release -p algod-rust --test live_msgpack_parity -- --ignored --nocapture --test-threads=1 && \
	 cargo test --release -p algod-rust --test live_auth_parity -- --ignored --nocapture && \
	 cargo test --release -p algod-rust --test live_headers_parity -- --ignored --nocapture && \
	 cargo test --release -p algod-rust --test live_endpoint_sweep -- --ignored --nocapture && \
	 cargo test --release -p algod-rust --test live_txn_cross_verification -- --ignored --nocapture --test-threads=1 && \
	 cargo test --release -p algod-rust --test live_box_pagination_parity -- --ignored --nocapture --test-threads=1 && \
	 cargo test --release -p algod-rust --test live_state_delta_parity -- --ignored --nocapture --test-threads=1 && \
	 cargo test --release -p algod-rust --test live_longpoll_parity -- --ignored --nocapture --test-threads=1 && \
	 cargo test --release -p algod-rust --test live_online_circulation_expiry -- --ignored --nocapture --test-threads=1; \
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

## ── vFuture Fixture Capture (issue #548) ──────────────────────
## A single-node, 100%-stake go-algorand private network pinned to the
## `future` consensus protocol, with MaxTxnBytesPerBlock shrunk (see
## docker/config/vfuture-consensus.json) so a small transaction burst can
## push a block's Load/CongestionTax ("ld"/"ct") header fields non-zero.
## See docs/DEV_WORKFLOW.md -> "vFuture Fixture Capture".

vfuture-up:
	$(COMPOSE_VFUTURE) up -d
	@echo "Waiting for algod-go-vfuture to be healthy..."
	@until docker inspect --format='{{.State.Health.Status}}' algod-go-vfuture 2>/dev/null | grep -q healthy; do \
		sleep 1; \
	done
	@echo "algod-go-vfuture is healthy — REST API on http://localhost:4010"

vfuture-down:
	$(COMPOSE_VFUTURE) down -v

vfuture-status:
	@curl -s http://localhost:4010/v2/status \
		-H "X-Algo-API-Token: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | python3 -m json.tool

## Full pipeline: brings the network up, floods it with transactions until
## Load/CongestionTax go non-zero, captures the golden fixtures, tears the
## network down. Requires a built `algod-rust` binary (release preferred):
##   cargo build --release --bin algod-rust
vfuture-fixtures:
	bash docker/scripts/capture-vfuture-fixtures.sh

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

## ── Mixed-cluster consensus harness (Epic 42, issue #107) ──────
##
## 3 go-algorand relays (30% of online stake each) + 1 `algod-rust
## participate` node (10%), all four voting. See
## ops/mixed-cluster/README.md for the sortition math and
## docs/PHASE6_VALIDATION.md for what each target proves.
##
## Canonical target family — everything that drives the
## ops/mixed-cluster harness is `consensus-cluster-*`:
##
##   consensus-cluster-up        bring the 4 nodes up
##   consensus-cluster-status    per-node round snapshot
##   consensus-cluster-down      tear down (PURGE=1 wipes netroot/)
##   consensus-cluster-smoke     #469 participation smoke test
##   consensus-cluster-test      #470 positive conformance suite
##   consensus-cluster-restart   #471 restart/rejoin scenarios
##   consensus-cluster-negative  #472 negative conformance suite
##   consensus-cluster-analyzer  soak-analyzer unit tests (no Docker)
##
## `phase6-cluster-*`, `consensus-analyzer-test` and
## `consensus-negative-test` remain as deprecated aliases at the bottom
## of this section.
consensus-cluster-up: ## Bring up the 4-node (3 Go + 1 Rust participant) consensus cluster
	$(PHASE6_CLUSTER)/scripts/start.sh

consensus-cluster-status: ## Per-node round snapshot for the consensus cluster (all 4 via REST)
	$(PHASE6_CLUSTER)/scripts/status.sh

consensus-cluster-down: ## Tear down the consensus cluster (pass PURGE=1 to wipe netroot/)
	@if [ "$(PURGE)" = "1" ]; then \
		$(PHASE6_CLUSTER)/scripts/stop.sh --purge; \
	else \
		$(PHASE6_CLUSTER)/scripts/stop.sh; \
	fi

consensus-cluster-smoke: ## Run the #469 participation smoke test (up + 30 rounds + assertions + down)
	SMOKE_ROUNDS=$(or $(SMOKE_ROUNDS),30) $(PHASE6_CLUSTER)/scripts/participation-smoke.sh

## Issue #470 (Epic 42c) — the full positive Layer-9 conformance suite:
## up -> forced period advancement -> soak -> verify (forks, certs both
## directions, proposer share, vote steps, cadence) -> down, with a
## machine-readable summary JSON. Override the round count with
## `make consensus-cluster-test ROUNDS=500`.
##
## Issue #471 (Epic 42d) adds an OPT-IN restart/rejoin stage to the same
## run — graceful restart, SIGKILL, and a restart timed into a round the
## Rust node is proposing in, each asserting rejoin-within-budget, no
## stall, no fork, and no equivocation across the restart boundary:
##
##   make consensus-cluster-test RESTART_SCENARIOS=1
##   make consensus-cluster-restart          # restart stage only, on an
##                                           # already-running cluster
##
## NEGATIVE_CASES=1 additionally runs the #472 negative suite (one malformed
## agreement message per case injected into go-node-1, asserting Go rejects
## each one and the cluster stays healthy) against the same running cluster.
consensus-cluster-test: consensus-cluster-analyzer ## Run the #470 conformance suite (up + soak + verify + down)
	cargo build -p algo-fork-detector -p algo-cert-crossverify -p algo-agreement-fuzz
	ROUNDS=$(or $(ROUNDS),200) \
	RESTART_SCENARIOS=$(or $(RESTART_SCENARIOS),0) \
	RESTART_MODE=$(or $(RESTART_MODE),all) \
	NEGATIVE_CASES=$(or $(NEGATIVE_CASES),0) \
		$(PHASE6_CLUSTER)/scripts/consensus-conformance.sh

consensus-cluster-restart: ## Run the #471 restart/rejoin scenarios against a RUNNING cluster
	cargo build -p algo-fork-detector
	MODE=$(or $(RESTART_MODE),all) $(PHASE6_CLUSTER)/scripts/restart-rejoin.sh

consensus-cluster-negative: ## Run the #472 negative conformance suite (up + inject 4 bad messages + down)
	cargo build -p algo-agreement-fuzz
	CASES=$(or $(CASES),bad-vrf-proof wrong-committee-weight wrong-ots-domain malformed-proposal) \
	SKIP_START=$(or $(SKIP_START),0) \
	KEEP_CLUSTER=$(or $(KEEP_CLUSTER),0) \
		$(PHASE6_CLUSTER)/scripts/negative-conformance.sh

consensus-cluster-analyzer: ## Unit-test the #470 soak-analyzer logic (no Docker needed)
	python3 $(PHASE6_CLUSTER)/scripts/analyze_test.py

## ops/mixed-cluster-p2p harness (issues #543, #560, #564, #589) — three
## real go-algorand v4.7.3-stable nodes in plain P2P mode, chain-bootstrapped
## to each other (1 <- 2 <- 3, no node told about a non-adjacent peer),
## dialed by algod-rust's `algo-p2p` libp2p transport to prove real
## cross-implementation transport interop, PLUS a 4th `rust-node-4` service
## holding real online stake and running `algod-rust participate
## --enable-p2p` as a genuine consensus participant (#589) — the P2P
## analogue of `ops/mixed-cluster/`'s WS-gossip 3-Go+1-Rust proof. See
## docs/MIXED_CLUSTER_HARNESS.md's "P2P interop harness" section for
## history — building this harness's 3-node chain found and fixed a DHT
## protocol-string bug (#560/#563), a DHT provider-record key-derivation
## bug (#564), a harness NetAddress/addressFilter config bug that silently
## blocked multi-hop DHT provider-record propagation between nodes (#566),
## and the fact that go-algorand only gossips the TX tag over gossipsub in
## P2P mode — AV/PP/VB agreement traffic travels over a raw
## `/algorand-ws/2.2.0` libp2p stream instead (#560, now implemented in
## `algo_p2p::wsproto` + `p2p_transport.rs`).
p2p-interop-up: ## Bring up the 4-node P2P interop target (3 Go + 1 stake-holding Rust)
	$(P2P_INTEROP_CLUSTER)/scripts/start.sh

p2p-interop-down: ## Tear down the P2P interop target (pass PURGE=1 to wipe netroot/)
	@if [ "$(PURGE)" = "1" ]; then \
		$(P2P_INTEROP_CLUSTER)/scripts/stop.sh --purge; \
	else \
		$(P2P_INTEROP_CLUSTER)/scripts/stop.sh; \
	fi

p2p-interop-test: p2p-interop-up ## Up + run the live interop test + down
	@ALGOD_RUST_P2P_GO_MULTIADDR="$$(cat $(P2P_INTEROP_CLUSTER)/netroot/.p2p-multiaddr-1)" \
	ALGOD_RUST_P2P_GO_MULTIADDR_2="$$(cat $(P2P_INTEROP_CLUSTER)/netroot/.p2p-multiaddr-2)" \
		cargo test --package algod-rust --test p2p_go_algorand_interop -- --ignored --nocapture; \
	status=$$?; \
	$(P2P_INTEROP_CLUSTER)/scripts/stop.sh; \
	exit $$status

p2p-interop-status: ## Per-node round snapshot for the P2P interop cluster (all 4 via REST)
	$(P2P_INTEROP_CLUSTER)/scripts/status.sh

## Issue #589 — the P2P-transport analogue of `consensus-cluster-test`
## (#469/#470): rust-node-4 in this harness now holds Wallet4's 10% online
## stake and runs `algod-rust participate --enable-p2p` (P2pOnly mode, no
## WS-gossip listener at all), dialing go-node-1 over
## `--p2p-bootstrap-peers`. consensus-round-trip.sh asserts the 4-node
## cluster reaches and maintains consensus over a run of rounds, mirroring
## participation-smoke.sh's assertions (lockstep, Rust round progress, no
## Go-side agreement rejections) but purely over the P2P transport.
p2p-interop-consensus-test: ## Up + run the #589 consensus round-trip assertion + down
	$(P2P_INTEROP_CLUSTER)/scripts/consensus-round-trip.sh

## Issue #594 — the P2P-transport analogue of `consensus-cluster-test`'s
## soak stage: a long (>= 200 round) run against the running P2P cluster,
## collecting per-round JSONL metrics (scripts/metrics.py) and analyzing
## them (the shared ops/mixed-cluster/scripts/analyze.py verifier) for
## proposer share, vote-step coverage, cadence and lockstep. Unlike
## `consensus-cluster-test` this does NOT run the fork-detector / bidirectional
## cert-cross-verify / restart / negative stages — those tools aren't wired to
## this harness yet (see docs/P2P_SOAK_METHODOLOGY.md).
##
##   make p2p-interop-soak-test ROUNDS=200
p2p-interop-soak: ## Run the #594 soak only (assumes an already-running cluster)
	$(P2P_INTEROP_CLUSTER)/scripts/soak.sh --rounds $(or $(ROUNDS),200)

## Issue #596 adds three OPT-IN stages to the same soak-suite invocation,
## mirroring consensus-cluster-test's own RESTART_SCENARIOS=1 (fork
## detector + bidirectional cert cross-verify is gated by VERIFY_STAGE=1
## here rather than being unconditional, since this harness's nightly
## Tier 1/Tier 2 split — see .github/workflows/p2p-consensus-soak.yml —
## keeps the expensive libsodium-backed go-authenticate step out of every
## soak run by default); issue #597 adds a fourth, NEGATIVE_CASES=1
## (P2P-speaking malformed-message injection):
##
##   VERIFY_STAGE=1 RESTART_SCENARIOS=1 NEGATIVE_CASES=1 make p2p-interop-soak-test
##
## `p2p-interop-verify` / `p2p-interop-restart` / `p2p-interop-negative`
## below run each stage standalone against an already-running cluster
## (SKIP_START-style usage from consensus-cluster.yml's Tier 2 job).
p2p-interop-soak-test: ## Run the #594 soak suite (up + soak + analyze + down); VERIFY_STAGE=1/RESTART_SCENARIOS=1/NEGATIVE_CASES=1 add #596/#597's stages
	cargo build -p algo-fork-detector -p algo-cert-crossverify -p algo-agreement-fuzz
	ROUNDS=$(or $(ROUNDS),200) \
	VERIFY_STAGE=$(or $(VERIFY_STAGE),0) \
	RESTART_SCENARIOS=$(or $(RESTART_SCENARIOS),0) \
	RESTART_MODE=$(or $(RESTART_MODE),all) \
	NEGATIVE_CASES=$(or $(NEGATIVE_CASES),0) \
		$(P2P_INTEROP_CLUSTER)/scripts/consensus-soak.sh

p2p-interop-verify: ## Run the #596 fork-detector + bidirectional cert cross-verify stage against a RUNNING P2P cluster
	cargo build -p algo-fork-detector -p algo-cert-crossverify
	$(P2P_INTEROP_CLUSTER)/scripts/verify-soak.sh --stride $(or $(CERT_STRIDE),20)

p2p-interop-restart: ## Run the #596 restart/rejoin scenarios against a RUNNING P2P cluster
	cargo build -p algo-fork-detector
	MODE=$(or $(RESTART_MODE),all) $(P2P_INTEROP_CLUSTER)/scripts/restart-rejoin.sh

p2p-interop-negative: ## Run the #597 negative conformance suite against a RUNNING P2P cluster (inject 4 bad messages over /algorand-ws/2.2.0)
	cargo build -p algo-agreement-fuzz
	CASES=$(or $(CASES),bad-vrf-proof wrong-committee-weight wrong-ots-domain malformed-proposal) \
	SKIP_START=$(or $(SKIP_START),1) \
	KEEP_CLUSTER=$(or $(KEEP_CLUSTER),1) \
		$(P2P_INTEROP_CLUSTER)/scripts/negative-conformance.sh

## Deprecated aliases.
##
## `phase6-cluster-*` was the TASK-86 name for the same harness back when
## the Rust node was a non-participating relay. `consensus-analyzer-test`
## and `consensus-negative-test` were introduced by #470/#472 before the
## family settled on the `consensus-cluster-*` prefix the epic (#107)
## names. All are kept so existing docs/muscle memory keep working;
## prefer the canonical names above.
consensus-analyzer-test: ## DEPRECATED alias for consensus-cluster-analyzer
	@echo "note: consensus-analyzer-test is deprecated — use 'make consensus-cluster-analyzer'" >&2
	@$(MAKE) consensus-cluster-analyzer

## Issue #496 (Phase 7) — the sibling 3 Go + 3 Rust, 50/50-stake
## topology. See ops/mixed-cluster-3rust/README.md for why it's a
## sibling directory rather than a mode of the harness above: this
## topology makes Rust cert votes quorum-necessary (`agreement.
## makeBundle` cannot clear 74.1% cert quorum from the Go side's ~50%
## alone), which the above harness's 30/30/30/10 split deliberately
## avoids so a Rust bug can never halt the chain.
.PHONY: consensus-cluster-3rust-up consensus-cluster-3rust-down consensus-cluster-3rust-status
.PHONY: consensus-cluster-3rust-soak consensus-cluster-3rust-verify
consensus-cluster-3rust-up: ## Bring up the 6-node (3 Go + 3 Rust, 50/50 stake) consensus cluster
	$(PHASE7_CLUSTER)/scripts/start.sh

consensus-cluster-3rust-status: ## Per-node round snapshot for the 3rust cluster (all 6 via REST)
	$(PHASE7_CLUSTER)/scripts/status.sh

consensus-cluster-3rust-down: ## Tear down the 3rust cluster (pass PURGE=1 to wipe netroot/)
	@if [ "$(PURGE)" = "1" ]; then \
		$(PHASE7_CLUSTER)/scripts/stop.sh --purge; \
	else \
		$(PHASE7_CLUSTER)/scripts/stop.sh; \
	fi

consensus-cluster-3rust-soak: ## Soak the 3rust cluster (ROUNDS, default 200); cluster must already be up
	$(PHASE7_CLUSTER)/scripts/soak.sh --rounds $(or $(ROUNDS),200)

consensus-cluster-3rust-verify: ## Fork + cert cross-verify (both directions) on the 3rust cluster
	cargo build -p algo-fork-detector -p algo-cert-crossverify
	$(PHASE7_CLUSTER)/scripts/verify-soak.sh \
		--rust-account "$(RUST_ACCOUNT)" \
		--min-rust-vote-rounds $(or $(MIN_RUST_VOTE_ROUNDS),5)

consensus-negative-test: ## DEPRECATED alias for consensus-cluster-negative
	@echo "note: consensus-negative-test is deprecated — use 'make consensus-cluster-negative'" >&2
	@$(MAKE) consensus-cluster-negative CASES="$(CASES)" SKIP_START=$(SKIP_START) KEEP_CLUSTER=$(KEEP_CLUSTER)

phase6-cluster-up: ## DEPRECATED alias for consensus-cluster-up
	@echo "note: phase6-cluster-up is deprecated — use 'make consensus-cluster-up'" >&2
	@$(MAKE) consensus-cluster-up

phase6-cluster-status: ## DEPRECATED alias for consensus-cluster-status
	@echo "note: phase6-cluster-status is deprecated — use 'make consensus-cluster-status'" >&2
	@$(MAKE) consensus-cluster-status

phase6-cluster-down: ## DEPRECATED alias for consensus-cluster-down
	@echo "note: phase6-cluster-down is deprecated — use 'make consensus-cluster-down'" >&2
	@$(MAKE) consensus-cluster-down PURGE=$(PURGE)

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

## Issue #100: 6-node mixed cluster (1 Go relay + 1 Rust relay, 2 Go + 2 Rust
## participation nodes) driven at a sustained TPS target by `algod-rust
## loadgen`. Defaults are a laptop-sized smoke run; override on the command
## line for the issue's aspirational load, e.g.
##   make bench-stress STRESS_ARGS="--target-tps 1000 --sustained-secs 300"
STRESS_ARGS ?=

bench-stress: ## Run the 6-node mixed-cluster stress benchmark (requires Docker)
	bash docker/scripts/bench-stress.sh $(STRESS_ARGS)

bench-stress-down: ## Tear down a cluster left running by `bench-stress --keep-up`
	docker compose -f docker/docker-compose.stress-test.yml down -v --remove-orphans

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
	@echo '                        go-algorand@v4.7.3-stable `algokey` on PATH for the'
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
	@echo "Mixed-Cluster Consensus (3 Go + 1 Rust, all four participating — Epic 42/#107):"
	@echo "  make consensus-cluster-up       Bring up the 4-node consensus cluster"
	@echo "  make consensus-cluster-status   Per-node round snapshot (all 4 via REST)"
	@echo "  make consensus-cluster-down     Tear down (append PURGE=1 to wipe netroot/)"
	@echo "  make consensus-cluster-smoke    #469 up + 30 rounds + lockstep/rejection asserts + down"
	@echo "  make consensus-cluster-test     #470 positive suite (up + 200-round soak + verify + down)"
	@echo "                                  ROUNDS=N, RESTART_SCENARIOS=1, NEGATIVE_CASES=1"
	@echo "  make consensus-cluster-restart  #471 restart/rejoin scenarios against a running cluster"
	@echo "  make consensus-cluster-negative #472 negative suite (inject 4 faulted messages, assert reject)"
	@echo "  make consensus-cluster-analyzer Unit-test the #470/#473 soak analyzer (no Docker)"
	@echo "  Evidence map: docs/PHASE6_VALIDATION.md; runbook: ops/mixed-cluster/README.md"
	@echo "  Deprecated aliases: phase6-cluster-up/-status/-down,"
	@echo "                      consensus-analyzer-test, consensus-negative-test"
	@echo ""
	@echo "P2P Mixed-Cluster Consensus (3 Go P2P + 1 Rust P2pOnly — #543/#560/#589/#594/#596/#597):"
	@echo "  make p2p-interop-up             Bring up the 4-node P2P consensus cluster"
	@echo "  make p2p-interop-status         Per-node round snapshot (all 4 via REST)"
	@echo "  make p2p-interop-down           Tear down (append PURGE=1 to wipe netroot/)"
	@echo "  make p2p-interop-test           #543 single-Go-node transport interop test"
	@echo "  make p2p-interop-consensus-test #589 up + 30-round consensus round-trip + down"
	@echo "  make p2p-interop-soak           #594 soak only (assumes a running cluster), ROUNDS=N"
	@echo "  make p2p-interop-soak-test      #594 full suite (up + soak + analyze + down), ROUNDS=N"
	@echo "                                  VERIFY_STAGE=1, RESTART_SCENARIOS=1 (#596), NEGATIVE_CASES=1 (#597)"
	@echo "  make p2p-interop-verify         #596 fork detector + bidirectional cert cross-verify (running cluster)"
	@echo "  make p2p-interop-restart        #596 restart/rejoin scenarios against a running cluster"
	@echo "  make p2p-interop-negative       #597 negative suite (inject 4 faulted messages over /algorand-ws/2.2.0)"
	@echo "  Runbook: ops/mixed-cluster-p2p/README.md;"
	@echo "  soak methodology: docs/P2P_SOAK_METHODOLOGY.md"
	@echo ""
	@echo "Benchmarks (fair comparison):"
	@echo "  make bench-micro      Run Rust criterion microbenchmarks (fixture-based)"
	@echo "  make bench-micro-go   Run Go decode microbenchmarks (same fixture files)"
	@echo "  make bench-cluster    Run mixed-cluster Go vs Rust comparison (Docker)"
	@echo "  make bench-stress     Run the 6-node mixed-cluster stress benchmark (Docker)"
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
