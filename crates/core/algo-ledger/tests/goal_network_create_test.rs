//! Parity tests against artifacts produced by a real `goal network create`
//! run (go-algorand v4.5.1-stable) — GitHub issue #468.
//!
//! The existing `partkey_reader_test.rs` fixture came from
//! `algokey part generate`. That tool and `goal network create` take
//! *different* code paths into `account.FillDBWithParticipationKeys`
//! (`gen/generate.go` picks its own `partKeyDilution` and validity window,
//! and always writes a state-proof blob), so a partkey emitted by the
//! network generator is a genuinely distinct artifact. These tests prove
//! the restore + registry-install path handles it identically.
//!
//! ## Fixture capture
//!
//! Both fixtures under `tests/fixtures/partkey/goal-network-create/` were
//! produced by running the official pinned image (the same one
//! `ops/mixed-cluster/scripts/start.sh` uses) over
//! `ops/mixed-cluster/template.json` with `NUM_ROUNDS=1500`:
//!
//! ```bash
//! sed 's/NUM_ROUNDS/1500/' ops/mixed-cluster/template.json > /tmp/template.json
//! docker run --rm \
//!     -v /tmp/netroot:/netroot \
//!     -v /tmp/template.json:/template.json:ro \
//!     --entrypoint goal algorand/algod:4.5.1-stable \
//!     network create -n phase6net -r /netroot -t /template.json
//! cp /tmp/netroot/Wallet1.0.1500.partkey \
//!    crates/core/algo-ledger/tests/fixtures/partkey/goal-network-create/
//! cp /tmp/netroot/genesis.json \
//!    crates/core/algo-ledger/tests/fixtures/partkey/goal-network-create/
//! ```
//!
//! The partkey bytes are byte-identical to the copy `goal` placed in
//! `netroot/Node1/phase6net-v1/`, and a real `algod` from the same image
//! was booted on that tree (proving Go's own `loadParticipationKeys`
//! accepts the file unchanged) before the fixture was taken.
//!
//! ## Why the two fixtures are checked together
//!
//! `goal network create` derives the genesis `alloc[].state` participation
//! fields *from* the partkey it just generated, so genesis.json is an
//! independent, human-readable transcript of what the partkey must contain.
//! Asserting the restored `Participation`'s public keys against the base64
//! in genesis.json is therefore a cross-artifact parity check, not a
//! self-consistent round-trip.
//!
//! ## Expected supply values
//!
//! `online-money` / `total-money` below were read from a live
//! `algorand/algod:4.5.1-stable` node booted on `netroot/Node1` at round 0:
//!
//! ```text
//! GET /v2/ledger/supply
//! {"current_round":0,"online-money":9900000000000000,"total-money":10000000000000000}
//! ```

use std::path::PathBuf;

use algo_ledger::erasable_db::ErasableDb;
use algo_ledger::participation::{
    generate_registration_transaction, restore_participation, Participation, ParticipationStore,
};
use algo_ledger::{
    apply_block, parse_genesis_json, populate_store, seed_account_totals_from_genesis, LedgerState,
    SqliteLedger,
};
use algo_types::{AccountStatus, Address, Block, Round, SignedTransaction};
use data_encoding::BASE64;

// ── Values transcribed from the captured genesis.json ──────────────────

/// `alloc[].comment == "Wallet1"` — the account `goal` bound the fixture
/// partkey to.
const WALLET1_ADDR: &str = "TO2V5UP4UGHPVJPY4BBIAVNDF2SYGHCSL6DH5VNLSVCUBZ42BJFJZFKXCE";
/// `alloc[].comment == "Wallet4"` — `"Online": false` in the template, so
/// `goal` generated *no* partkey for it. This is the offline-genesis case.
const WALLET4_ADDR: &str = "Q7FTH4YCVX7WF5P7DSQ5GYMZHPZEYMZUZEJWGDQX5W3KJG4JFGSDTWX5TI";

/// Wallet1's `state.vote` — the OTS master verifier.
const WALLET1_VOTE_B64: &str = "NckDdHw8unbXsSTmFAXzoYF8qBNOsTVx7IU0E5iHS2A=";
/// Wallet1's `state.sel` — the VRF public key.
const WALLET1_SEL_B64: &str = "UNw/jukd5gsZUKHtnZlGO49TaGZhMVeeYVNbe7o46jw=";
/// Wallet1's `state.stprf` — the merkle-signature commitment (64 bytes).
const WALLET1_STPRF_B64: &str =
    "0IffoBIHLqZJpoRCemHR0bYCDloyoVV4rtBuyJ+h17fOuw0RoV9KXCdObXnh+N9Bv8S248M+jm+r5BghhkyzOA==";

/// `state.voteKD` for every online wallet.
const GOAL_KEY_DILUTION: u64 = 10_000;
/// The `FirstPartKeyRound` / `LastPartKeyRound` from the template.
const GOAL_FIRST_VALID: u64 = 0;
const GOAL_LAST_VALID: u64 = 1500;

/// `online-money` from the live Go node's `/v2/ledger/supply` at round 0.
const GO_ONLINE_MONEY: u64 = 9_900_000_000_000_000;
/// `total-money` from the same response. Go reports
/// `AccountTotals.Participating()` = Online + Offline, which deliberately
/// EXCLUDES the `NotParticipating` fee sink and rewards pool.
const GO_TOTAL_MONEY: u64 = 10_000_000_000_000_000;

// ── Fixture helpers ────────────────────────────────────────────────────

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/partkey/goal-network-create")
}

fn partkey_path() -> PathBuf {
    fixture_dir().join("Wallet1.0.1500.partkey")
}

fn genesis_json() -> String {
    std::fs::read_to_string(fixture_dir().join("genesis.json")).expect("read genesis.json fixture")
}

/// Open the read-only fixture. SQLite wants to create sidecar journal files
/// next to the database even for pure reads, so callers that need a
/// writable handle must copy first; the read-only opener avoids that.
fn restore_fixture() -> Participation {
    let db = ErasableDb::open_read_only(partkey_path()).expect("open goal-network-create partkey");
    restore_participation(&db).expect("restore goal-network-create partkey")
}

fn b64(s: &str) -> Vec<u8> {
    BASE64.decode(s.as_bytes()).expect("decode fixture base64")
}

// ── 1. Restore parity: partkey vs. genesis.json ────────────────────────

#[test]
fn restores_metadata_from_goal_network_create_partkey() {
    let p = restore_fixture();
    assert_eq!(
        p.parent.to_string(),
        WALLET1_ADDR,
        "parent must be the Wallet1 address goal allocated in genesis"
    );
    assert_eq!(p.first_valid.0, GOAL_FIRST_VALID);
    assert_eq!(p.last_valid.0, GOAL_LAST_VALID);
    // `goal network create` uses a fixed dilution rather than
    // `algokey`'s sqrt-of-range default — the whole reason this fixture
    // exists alongside `small.sqlite`.
    assert_eq!(p.key_dilution, GOAL_KEY_DILUTION);
}

/// `first_valid == 0` is exclusive to the network generator (the template's
/// `FirstPartKeyRound` is 0, whereas `algokey part generate` refuses 0 in
/// most flows). Pin it: a reader that silently coerced 0 → 1 would produce
/// a key whose OTS batch numbering is off by one against Go's.
#[test]
fn first_valid_round_zero_is_preserved() {
    let p = restore_fixture();
    assert_eq!(p.first_valid, Round(0));
    let (first, last) = p.valid_interval();
    assert_eq!((first.0, last.0), (GOAL_FIRST_VALID, GOAL_LAST_VALID));
}

#[test]
fn vote_pubkey_matches_genesis_alloc() {
    let p = restore_fixture();
    assert_eq!(
        p.voting.verifier().to_vec(),
        b64(WALLET1_VOTE_B64),
        "OTS verifier diverges from the `vote` goal wrote into genesis.json"
    );
}

#[test]
fn vrf_pubkey_matches_genesis_alloc() {
    let p = restore_fixture();
    assert_eq!(
        p.vrf.pk.0.to_vec(),
        b64(WALLET1_SEL_B64),
        "VRF pubkey diverges from the `sel` goal wrote into genesis.json"
    );
}

/// Unlike the `algokey` fixture — whose 1..100 window never crosses a
/// 256-round state-proof boundary — the network generator's 0..1500 window
/// does, so this artifact actually carries a state-proof blob. Restoring it
/// must reproduce the commitment goal published as `stprf`.
#[test]
fn state_proof_commitment_matches_genesis_alloc() {
    let p = restore_fixture();
    let secrets = p
        .state_proof_secrets
        .as_ref()
        .expect("goal network create always writes state-proof secrets");
    assert_eq!(
        secrets.get_verifier().commitment.to_vec(),
        b64(WALLET1_STPRF_B64),
        "state-proof commitment diverges from the `stprf` in genesis.json"
    );
}

/// The keyreg builder must round-trip the same three public keys, so a
/// `goal network create` key can be re-registered by algod-rust without
/// changing the account's on-chain participation identity.
#[test]
fn keyreg_txn_from_goal_partkey_carries_genesis_pubkeys() {
    let p = restore_fixture();
    let txn = generate_registration_transaction(&p, 1000, Round(1), Round(1000), [0u8; 32], true);
    assert_eq!(txn.sender.to_string(), WALLET1_ADDR);
    assert_eq!(
        txn.vote_pk.expect("vote_pk").to_vec(),
        b64(WALLET1_VOTE_B64)
    );
    assert_eq!(
        txn.selection_pk.expect("selection_pk").to_vec(),
        b64(WALLET1_SEL_B64)
    );
    assert_eq!(
        txn.state_proof_pk.expect("state_proof_pk").to_vec(),
        b64(WALLET1_STPRF_B64)
    );
    assert_eq!(txn.vote_first, GOAL_FIRST_VALID);
    assert_eq!(txn.vote_last, GOAL_LAST_VALID);
    assert_eq!(txn.vote_key_dilution, GOAL_KEY_DILUTION);
    assert!(!txn.non_participation);
}

// ── 2. Registry install ────────────────────────────────────────────────

/// The single-account partkey schema and the multi-key registry schema are
/// different databases. Prove the bridge: restore the goal artifact, insert
/// it into a `ParticipationStore`, and read back a record that still
/// carries every field consensus needs.
#[test]
fn goal_partkey_installs_into_the_registry() {
    let p = restore_fixture();
    let store = ParticipationStore::open_in_memory().expect("open registry");
    let id = store.insert(&p).expect("insert into registry");
    assert_eq!(id, p.id(), "registry ID must be the partkey's own ID");

    let all = store.get_all().expect("get_all");
    assert_eq!(all.len(), 1);
    let rec = &all[0];
    assert_eq!(rec.account.to_string(), WALLET1_ADDR);
    assert_eq!(rec.first_valid.0, GOAL_FIRST_VALID);
    assert_eq!(rec.last_valid.0, GOAL_LAST_VALID);
    assert_eq!(rec.key_dilution, GOAL_KEY_DILUTION);
    assert_eq!(
        rec.vote_id.expect("vote_id").to_vec(),
        b64(WALLET1_VOTE_B64),
        "registry lost the OTS verifier — the key would be filtered out of consensus"
    );
    assert_eq!(
        rec.vrf_public_key.expect("vrf key").0.to_vec(),
        b64(WALLET1_SEL_B64),
        "registry lost the VRF key — sortition would be impossible"
    );
}

/// Re-importing the same key must not error: a participate container that
/// restarts against a persistent registry volume has to converge, not
/// crash-loop on `UNIQUE(participationID)`. The bridge in
/// `bin/algod-rust/src/commands/participate.rs` relies on the violation
/// being a *constraint* failure specifically.
#[test]
fn reinstalling_the_same_goal_partkey_is_a_constraint_violation() {
    let p = restore_fixture();
    let store = ParticipationStore::open_in_memory().expect("open registry");
    store.insert(&p).expect("first insert");
    let err = store.insert(&p).expect_err("second insert must fail");
    match err {
        rusqlite::Error::SqliteFailure(ffi, _) => assert_eq!(
            ffi.code,
            rusqlite::ErrorCode::ConstraintViolation,
            "duplicate import must surface as a constraint violation so the \
             importer can treat it as a no-op"
        ),
        other => panic!("expected a constraint violation, got {other:?}"),
    }
    assert_eq!(store.get_all().expect("get_all").len(), 1);
}

/// The key is live for the whole template window and dead after it — the
/// property `participate`'s key manager uses to decide whether it can vote.
#[test]
fn goal_partkey_liveness_window_matches_the_template() {
    let p = restore_fixture();
    let store = ParticipationStore::open_in_memory().expect("open registry");
    store.insert(&p).expect("insert");
    assert!(store
        .has_live_keys(Round(0), Round(0))
        .expect("has_live_keys at genesis"));
    assert!(store
        .has_live_keys(Round(GOAL_LAST_VALID), Round(GOAL_LAST_VALID))
        .expect("has_live_keys at last valid"));
    assert!(
        !store
            .has_live_keys(Round(GOAL_LAST_VALID + 1), Round(GOAL_LAST_VALID + 1))
            .expect("has_live_keys past expiry"),
        "an expired key window must not report live keys"
    );
}

// ── 3. Negative paths ──────────────────────────────────────────────────

/// A partkey truncated mid-page (a half-finished `docker cp`, an aborted
/// bind-mount write) must be rejected, not silently restored with garbage.
#[test]
fn corrupt_partkey_is_rejected() {
    let bytes = std::fs::read(partkey_path()).expect("read fixture");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("corrupt.partkey");
    // Keep the SQLite header so the file still *looks* like a database,
    // then scribble over the payload.
    let mut corrupt = bytes[..4096].to_vec();
    for b in corrupt[100..].iter_mut() {
        *b ^= 0xFF;
    }
    std::fs::write(&path, &corrupt).expect("write corrupt partkey");

    let restored = match ErasableDb::open(&path) {
        // Opening may already fail (a mangled header/page map); if it
        // opens, the restore itself must reject the garbage.
        Ok(db) => restore_participation(&db).is_ok(),
        Err(_) => false,
    };
    assert!(
        !restored,
        "a corrupted partkey must not restore successfully"
    );
}

/// An empty (or freshly created) SQLite file has no `ParticipationAccount`
/// table. Go's `RestoreParticipation` fails here; so must ours.
#[test]
fn partkey_with_missing_tables_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("empty.partkey");
    // An ErasableDb open on a nonexistent path creates an empty database.
    let db = ErasableDb::open(&path).expect("create empty db");
    let msg = match restore_participation(&db) {
        Ok(_) => panic!("a database with no ParticipationAccount table must not restore"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.to_lowercase().contains("no such table")
            || msg.to_lowercase().contains("participation"),
        "error should identify the missing participation table, got: {msg}"
    );
}

// ── 4. Genesis seeding parity vs. Go's /v2/ledger/supply ───────────────

/// Seed a brand-new SQLite ledger from the captured `goal network create`
/// genesis.json and assert the two numbers a Go node serves from
/// `/v2/ledger/supply` at round 0.
///
/// This is the criterion-1 parity test: `participate --genesis-json` runs
/// exactly this `parse_genesis_json` → `populate_store` →
/// `seed_account_totals_from_genesis` sequence (see
/// `bin/algod-rust/src/commands/participate.rs::seed_ledger_from_genesis`).
#[test]
fn genesis_seed_matches_go_ledger_supply() {
    let dir = tempfile::tempdir().expect("tempdir");
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open(&prefix).expect("open fresh ledger");
    assert!(
        !ledger.has_account_totals().expect("has_account_totals"),
        "a fresh ledger must not claim to be seeded"
    );

    let genesis = parse_genesis_json(&genesis_json()).expect("parse goal genesis.json");
    ledger.begin_block().expect("begin_block");
    populate_store(&mut ledger, &genesis).expect("populate_store");
    seed_account_totals_from_genesis(&mut ledger, &genesis).expect("seed totals");
    ledger.commit_block().expect("commit_block");

    assert_eq!(
        ledger.online_stake().expect("online_stake"),
        GO_ONLINE_MONEY,
        "online circulation diverges from the Go node's /v2/ledger/supply online-money"
    );
    assert_eq!(
        ledger.participating_money().expect("participating_money"),
        GO_TOTAL_MONEY,
        "participating money diverges from the Go node's /v2/ledger/supply total-money"
    );
    assert!(
        ledger.has_account_totals().expect("has_account_totals"),
        "accounttotals row must exist after seeding"
    );
}

/// The seeded `accountbase` must carry per-account status, not just the
/// aggregate — sortition reads the account, not the totals row.
#[test]
fn genesis_seed_populates_accountbase_statuses() {
    let state =
        LedgerState::from_genesis_json(&genesis_json()).expect("build state from goal genesis");
    let w1 = Address::from_algorand_string(WALLET1_ADDR).expect("wallet1 addr");
    let w4 = Address::from_algorand_string(WALLET4_ADDR).expect("wallet4 addr");

    let a1 = state.accounts.get(&w1).expect("Wallet1 allocated");
    assert_eq!(a1.status, AccountStatus::Online);
    assert_eq!(a1.micro_algos, 3_300_000_000_000_000);
    assert_eq!(a1.vote_id.expect("vote_id").to_vec(), b64(WALLET1_VOTE_B64));
    assert_eq!(
        a1.selection_id.expect("selection_id").to_vec(),
        b64(WALLET1_SEL_B64)
    );
    assert_eq!(a1.vote_key_dilution, GOAL_KEY_DILUTION);
    assert_eq!(a1.vote_last_valid, GOAL_LAST_VALID);

    let a4 = state.accounts.get(&w4).expect("Wallet4 allocated");
    assert_eq!(
        a4.status,
        AccountStatus::Offline,
        "the template marks Wallet4 `\"Online\": false` — this is the case \
         that needs a keyreg to join consensus"
    );
    assert_eq!(a4.micro_algos, 100_000_000_000_000);
    assert!(
        a4.vote_id.is_none(),
        "an offline genesis account has no keys"
    );
}

/// Seeding is idempotent at the totals level: a restart against a populated
/// volume must not double-count. `seed_ledger_from_genesis` guards on the
/// `accounttotals` row, so re-running the seed would be skipped there;
/// this pins the underlying writer's overwrite (not accumulate) semantics.
#[test]
fn reseeding_totals_overwrites_rather_than_accumulates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open(&prefix).expect("open fresh ledger");
    let genesis = parse_genesis_json(&genesis_json()).expect("parse genesis");

    for _ in 0..2 {
        ledger.begin_block().expect("begin_block");
        populate_store(&mut ledger, &genesis).expect("populate_store");
        seed_account_totals_from_genesis(&mut ledger, &genesis).expect("seed totals");
        ledger.commit_block().expect("commit_block");
    }

    assert_eq!(
        ledger.online_stake().expect("online_stake"),
        GO_ONLINE_MONEY
    );
    assert_eq!(
        ledger.participating_money().expect("participating_money"),
        GO_TOTAL_MONEY
    );
}

/// A genesis whose allocations don't include the account whose partkey we
/// hold is an operator error worth surfacing early: the key restores fine,
/// but the account it names has no stake and can never be selected.
#[test]
fn partkey_account_absent_from_genesis_has_no_stake() {
    let state = LedgerState::from_genesis_json(&genesis_json()).expect("state");
    // A partkey generated for an address that goal never allocated.
    let stranger = Participation::generate(Address([7u8; 32]), Round(0), Round(100), 0, 256)
        .expect("generate stranger partkey");
    assert!(
        !state.accounts.contains_key(&stranger.parent),
        "the stranger account must not appear in the goal genesis"
    );
}

// ── 5. Keyreg-online end to end for the offline-genesis account ────────

/// Build a block carrying `payset`, protocol-pinned to V41.
fn block_with(round: u64, fee_sink: Address, payset: Vec<SignedTransaction>) -> Block {
    Block {
        round: Round(round),
        current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
        fee_sink,
        payset,
        ..Block::default()
    }
}

/// Wrap an unsigned keyreg `Transaction` in a `SignedTransaction` for
/// `apply_block`. Signature verification lives in `algo-validate`, not the
/// apply path, so an unsigned envelope is enough to exercise the state
/// transition.
fn signed(txn: algo_types::Transaction) -> SignedTransaction {
    SignedTransaction {
        txn,
        ..SignedTransaction::default()
    }
}

/// Criterion 4: the offline-genesis case. Wallet4 starts `Offline` with no
/// participation keys (goal generated none for it). Generate a key for it,
/// build the keyreg with the production builder, apply it, and assert the
/// account is Online with exactly the key material the partkey carries —
/// i.e. it is now eligible for sortition.
#[test]
fn keyreg_online_brings_offline_genesis_account_online() {
    let mut state =
        LedgerState::from_genesis_json(&genesis_json()).expect("state from goal genesis");
    let w4 = Address::from_algorand_string(WALLET4_ADDR).expect("wallet4 addr");
    assert_eq!(
        state.accounts.get(&w4).expect("wallet4").status,
        AccountStatus::Offline
    );
    let before = state.accounts.get(&w4).expect("wallet4").micro_algos;

    // Key window must cover the round the keyreg lands in.
    let part = Participation::generate(w4, Round(1), Round(2000), GOAL_KEY_DILUTION, 256)
        .expect("generate Wallet4 partkey");
    let txn = generate_registration_transaction(&part, 1_000, Round(1), Round(10), [0u8; 32], true);

    let fee_sink = state.fee_sink;
    apply_block(&mut state, &block_with(1, fee_sink, vec![signed(txn)]))
        .expect("apply keyreg block");

    let acct = state.accounts.get(&w4).expect("wallet4 after keyreg");
    assert_eq!(
        acct.status,
        AccountStatus::Online,
        "keyreg must bring the offline genesis account online"
    );
    assert_eq!(
        acct.vote_id.expect("vote_id"),
        part.voting.verifier(),
        "on-chain vote key must be the partkey's OTS verifier"
    );
    assert_eq!(
        acct.selection_id.expect("selection_id"),
        part.vrf.pk.0,
        "on-chain selection key must be the partkey's VRF pubkey"
    );
    assert_eq!(
        acct.state_proof_id.expect("state_proof_id"),
        part.state_proof_secrets
            .as_ref()
            .expect("state proof secrets")
            .get_verifier()
            .commitment
    );
    assert_eq!(acct.vote_first_valid, 1);
    assert_eq!(acct.vote_last_valid, 2000);
    assert_eq!(acct.vote_key_dilution, GOAL_KEY_DILUTION);
    assert_eq!(
        acct.micro_algos,
        before - 1_000,
        "keyreg fee must be debited"
    );
}

/// Negative path: a key whose window has already closed must be rejected
/// rather than registering a permanently unusable online account. Mirrors
/// Go's keyreg coherency check (`vote_last <= current round`).
#[test]
fn keyreg_with_expired_key_window_is_rejected() {
    let mut state =
        LedgerState::from_genesis_json(&genesis_json()).expect("state from goal genesis");
    let w4 = Address::from_algorand_string(WALLET4_ADDR).expect("wallet4 addr");
    // Fast-forward so the next block is round 100.
    state.current_round = Round(99);

    // Window 1..50, but the keyreg lands at round 100.
    let part = Participation::generate(w4, Round(1), Round(50), GOAL_KEY_DILUTION, 256)
        .expect("generate expired partkey");
    let txn =
        generate_registration_transaction(&part, 1_000, Round(90), Round(110), [0u8; 32], true);

    let fee_sink = state.fee_sink;
    let err = apply_block(&mut state, &block_with(100, fee_sink, vec![signed(txn)]))
        .expect_err("expired key window must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("vote_last"),
        "error should name the expired vote window, got: {msg}"
    );
    assert_eq!(
        state.accounts.get(&w4).expect("wallet4").status,
        AccountStatus::Offline,
        "a rejected keyreg must leave the account offline"
    );
}

/// The already-online case needs no keyreg: Wallet1 is `"Online": true` in
/// the template and genesis already carries its keys, so a fresh
/// `participate` node holding that partkey can vote at round 0 without
/// submitting anything. Pin that the genesis-seeded record and the
/// on-disk partkey agree, which is what makes the no-keyreg path valid.
#[test]
fn online_genesis_account_needs_no_keyreg() {
    let state = LedgerState::from_genesis_json(&genesis_json()).expect("state");
    let w1 = Address::from_algorand_string(WALLET1_ADDR).expect("wallet1 addr");
    let acct = state.accounts.get(&w1).expect("wallet1");
    assert_eq!(acct.status, AccountStatus::Online);

    let part = restore_fixture();
    assert_eq!(part.parent, w1);
    assert_eq!(
        acct.vote_id.expect("vote_id"),
        part.voting.verifier(),
        "genesis vote key must already equal the partkey's — no keyreg needed"
    );
    assert_eq!(acct.selection_id.expect("selection_id"), part.vrf.pk.0);
    assert_eq!(acct.vote_key_dilution, part.key_dilution);
    assert_eq!(acct.vote_last_valid, part.last_valid.0);
}
