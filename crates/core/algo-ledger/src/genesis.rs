// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;

use algo_error::AlgoError;
use algo_types::{AccountData, AccountStatus, Address};
use data_encoding::BASE64;
use serde::Deserialize;
use sha2::{Digest as _, Sha512_256};

use crate::state::LedgerState;

/// Parsed genesis.json representation.
///
/// Field set + JSON keys match
/// `../go-algorand/data/bookkeeping/genesis.go:44-84` byte-for-byte —
/// keeping them in sync is what makes the G7 genesis-hash computation
/// agree with Go.
#[derive(Debug, Deserialize)]
pub struct GenesisJson {
    pub network: String,
    pub id: String,
    pub proto: String,
    pub alloc: Vec<GenesisAllocation>,
    pub fees: String,
    pub rwd: String,
    /// Genesis block timestamp (seconds since epoch). Required for
    /// hash parity with Go — every shipped network's `genesis.json`
    /// carries this field (mainnet = 1560211200, etc.). Defaults to
    /// 0 so older test fixtures without the field still parse.
    #[serde(default)]
    pub timestamp: i64,
    /// Arbitrary genesis comment string. Go's `genesis.go` marks this
    /// as `omitempty` so we treat empty / missing identically.
    #[serde(default)]
    pub comment: Option<String>,
    /// Developer-mode network indicator. Go's `genesis.go`:
    /// "Developer mode networks are a single node network, that
    /// operates without the agreement service being active." Default
    /// false matches Go's omitempty behaviour.
    #[serde(default)]
    pub devmode: bool,
}

/// A single account allocation from genesis.json.
///
/// NOTE: in Go's `genesis.go:155-164`, `GenesisAllocation` is the
/// outlier — the comment explicitly says "we forgot to specify
/// omitempty, and now this struct must be encoded without omitempty
/// for the Address, Comment, and State fields." Our canonical
/// encoder must therefore emit `addr`, `comment`, and `state` for
/// every allocation, even when empty.
#[derive(Debug, Deserialize)]
pub struct GenesisAllocation {
    pub addr: String,
    /// `comment` is always serialized (no omitempty in Go), so we
    /// normalize JSON `null` / absent to the empty string at canonical-
    /// encoding time.
    #[serde(default)]
    pub comment: Option<String>,
    pub state: GenesisAccountState,
}

/// Account state fields within a genesis allocation.
#[derive(Debug, Deserialize)]
pub struct GenesisAccountState {
    #[serde(default)]
    pub algo: u64,
    pub onl: Option<u8>,
    pub sel: Option<String>,
    pub vote: Option<String>,
    #[serde(rename = "voteKD")]
    pub vote_kd: Option<u64>,
    #[serde(rename = "voteFst")]
    pub vote_fst: Option<u64>,
    #[serde(rename = "voteLst")]
    pub vote_lst: Option<u64>,
    pub stprf: Option<String>,
}

/// Resolve the account status a genesis allocation entry should actually get.
///
/// Only the **fee sink** is unconditionally forced to `NotParticipating`
/// regardless of the genesis file's declared `onl` value; the rewards pool
/// honors its declared status like any other account. Verified live
/// against go-algorand v4.6.0-stable with a *nonzero* rewards-pool balance
/// (issue #449) -- `GET /v2/accounts/{rewardsPool}` reports `"Offline"`
/// (matching this localnet genesis's `"onl": 0`), not `"Not Participating"`.
///
/// A prior version of this function also forced the rewards pool to
/// `NotParticipating`, based on an earlier live comparison that used a
/// **zero**-balance rewards pool (PR #446) -- with a zero balance, "Offline"
/// and "NotParticipating" are observationally identical in every
/// balance-aggregate response (`/v2/ledger/supply`'s `total-money`), so
/// that comparison could not actually distinguish the two hypotheses. Once
/// the rewards pool carries a real balance (needed to unblock go's
/// dev-mode block production at all -- see
/// `docker/localnet-rust/data/genesis.json`), the distinction becomes
/// observable and the original claim doesn't hold.
fn effective_genesis_status(
    addr: &str,
    state: &GenesisAccountState,
    fee_sink: &str,
) -> AccountStatus {
    if addr == fee_sink {
        return AccountStatus::NotParticipating;
    }
    match state.onl {
        Some(v) => AccountStatus::from(v),
        None => AccountStatus::Offline,
    }
}

/// Populate any `LedgerStore` backend from parsed genesis data.
///
/// Sets fee_sink, rewards_pool, genesis_id, protocol, genesis_hash,
/// and all account allocations. Can be used with both in-memory
/// `LedgerState` and SQLite backends.
///
/// The genesis hash is computed via [`genesis_hash`] —
/// `SHA512/256("GE" || canonical_encode_genesis(genesis))` — and
/// matches Go's `Genesis.Hash()` byte-for-byte for every shipped
/// network (mainnet / testnet / devnet / betanet — see the
/// `genesis_hash_matches_go_for_*` tests below).
pub fn populate_store<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    genesis: &GenesisJson,
) -> Result<(), AlgoError> {
    let fee_sink = Address::from_algorand_string(&genesis.fees).map_err(|e| AlgoError::Ledger {
        message: format!("invalid fee sink address '{}': {e}", genesis.fees),
    })?;
    let rewards_pool =
        Address::from_algorand_string(&genesis.rwd).map_err(|e| AlgoError::Ledger {
            message: format!("invalid rewards pool address '{}': {e}", genesis.rwd),
        })?;

    store.set_fee_sink(fee_sink);
    store.set_rewards_pool(rewards_pool);
    store.set_genesis_id(format!("{}-{}", genesis.network, genesis.id));
    store.set_genesis_hash(genesis_hash(genesis));
    store.set_protocol(genesis.proto.clone());

    // Process allocations
    for alloc in &genesis.alloc {
        let addr = Address::from_algorand_string(&alloc.addr).map_err(|e| AlgoError::Ledger {
            message: format!("invalid allocation address '{}': {e}", alloc.addr),
        })?;

        let status = effective_genesis_status(&alloc.addr, &alloc.state, &genesis.fees);

        let vote_id = decode_key_32(&alloc.state.vote, "vote")?;
        let selection_id = decode_key_32(&alloc.state.sel, "sel")?;
        let state_proof_id = decode_key_64(&alloc.state.stprf, "stprf")?;

        let account = AccountData {
            micro_algos: alloc.state.algo,
            status,
            vote_id,
            selection_id,
            state_proof_id,
            vote_first_valid: alloc.state.vote_fst.unwrap_or(0),
            vote_last_valid: alloc.state.vote_lst.unwrap_or(0),
            vote_key_dilution: alloc.state.vote_kd.unwrap_or(0),
            ..Default::default()
        };

        store.set_account(&addr, account);
    }

    Ok(())
}

/// Parse genesis JSON string into its typed representation.
pub fn parse_genesis_json(json_str: &str) -> Result<GenesisJson, AlgoError> {
    serde_json::from_str(json_str).map_err(|e| AlgoError::Ledger {
        message: format!("failed to parse genesis JSON: {e}"),
    })
}

// ===========================================================================
// G7: Canonical msgpack encoding + genesis hash
// ===========================================================================
//
// Mirrors Go's `Genesis.ToBeHashed`:
//   ../go-algorand/data/bookkeeping/genesis.go:167-169
//     return protocol.Genesis ("GE"), protocol.Encode(&genesis)
//   crypto.HashObj  → sha512.Sum512_256(HashID || msgpack(obj))
//
// Genesis is encoded by Go's `go-codec` library with
// `omitempty,omitemptyarray` on the struct, except for
// `GenesisAllocation` which is encoded WITHOUT omitempty
// ("we forgot to specify omitempty" comment in genesis.go:156).
// The reference implementation uses canonical msgpack (sorted keys).

/// HashID domain separator for genesis.
/// Go: `protocol/hash.go:46` → `Genesis HashID = "GE"`.
const HASH_DOMAIN_GENESIS: &[u8] = b"GE";

/// Canonically encode a `GenesisJson` into msgpack matching Go's
/// `protocol.Encode(&Genesis)` output. Keys are sorted
/// lexicographically; omitempty/omitemptyarray rules track Go's
/// codec tags exactly. The result is what gets hashed for
/// [`genesis_hash`].
pub fn canonical_encode_genesis(genesis: &GenesisJson) -> Vec<u8> {
    let mut fields: Vec<(&'static str, Vec<u8>)> = Vec::new();

    // "alloc" — never omitted in practice (Go's `omitemptyarray` skips
    // empty but every real genesis ships allocations).
    if !genesis.alloc.is_empty() {
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, genesis.alloc.len() as u32).unwrap();
        for a in &genesis.alloc {
            buf.extend_from_slice(&encode_allocation(a));
        }
        fields.push(("alloc", buf));
    }

    // "comment" — omitempty string.
    let comment = genesis.comment.as_deref().unwrap_or("");
    if !comment.is_empty() {
        fields.push(("comment", encode_str(comment)));
    }

    // "devmode" — omitempty bool (skip when false).
    if genesis.devmode {
        let mut buf = Vec::new();
        rmp::encode::write_bool(&mut buf, true).unwrap();
        fields.push(("devmode", buf));
    }

    // "fees", "id", "network", "proto", "rwd" — omitempty strings.
    if !genesis.fees.is_empty() {
        fields.push(("fees", encode_str(&genesis.fees)));
    }
    if !genesis.id.is_empty() {
        fields.push(("id", encode_str(&genesis.id)));
    }
    if !genesis.network.is_empty() {
        fields.push(("network", encode_str(&genesis.network)));
    }
    if !genesis.proto.is_empty() {
        fields.push(("proto", encode_str(&genesis.proto)));
    }
    if !genesis.rwd.is_empty() {
        fields.push(("rwd", encode_str(&genesis.rwd)));
    }

    // "timestamp" — omitempty i64 (skip when 0).
    if genesis.timestamp != 0 {
        let mut buf = Vec::new();
        encode_i64(&mut buf, genesis.timestamp);
        fields.push(("timestamp", buf));
    }

    // Sort by key — go-codec emits canonical maps with byte-sorted keys.
    fields.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    let mut out = Vec::new();
    rmp::encode::write_map_len(&mut out, fields.len() as u32).unwrap();
    for (k, v) in fields {
        rmp::encode::write_str(&mut out, k).unwrap();
        out.extend_from_slice(&v);
    }
    out
}

/// SHA512/256("GE" || canonical_encode_genesis(genesis)). Matches
/// Go's `Genesis.Hash()` byte-for-byte for every shipped network
/// (mainnet / testnet / devnet / betanet — verified by the tests
/// below).
pub fn genesis_hash(genesis: &GenesisJson) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(HASH_DOMAIN_GENESIS);
    hasher.update(canonical_encode_genesis(genesis));
    hasher.finalize().into()
}

/// Build the round-0 **genesis block** from parsed genesis data, porting
/// go-algorand's `bookkeeping.MakeGenesisBlock`
/// (`data/bookkeeping/genesis.go:218`). The genesis block has no transactions;
/// it exists so the ledger has a tip header to chain block 1 from (the
/// transaction pool's evaluator reads `block_hdr(latest)`), and so
/// `/v2/blocks/0` serves.
///
/// Faithful for the consequential header fields (round, protocol, seed =
/// genesis hash, rewards state, genesis hash/id, timestamp). Two go gating
/// consensus params are version-gated via [`algo_types::ConsensusParams`]
/// (`data/bookkeeping/genesis.go`'s `MakeGenesisBlock`), so a genesis built
/// under an older protocol reproduces go's canonical pre-fix behavior:
/// - `InitialRewardsRateCalculation` (v26+) → the rewards rate subtracts
///   `MinBalance` from the rewards-pool balance before dividing; before v26,
///   the whole pool balance is divided directly.
/// - `AppForbidLowResources` (v38+) → `TxnCounter` starts at 1000, so the
///   first created asset/app gets id 1001 like a real network; before v38,
///   it starts at 0 (first id 1).
///
/// `txn_commitment` is set to go's real empty-*non-nil*-payset commitment
/// (see [`GENESIS_EMPTY_PAYSET_COMMITMENT`]), matching
/// `bookkeeping.Payset{}.CommitGenesis()` in `../go-algorand`.
pub fn make_genesis_block(genesis: &GenesisJson) -> Result<algo_types::Block, AlgoError> {
    let params =
        algo_types::consensus::consensus_params_for_version(&genesis.proto).ok_or_else(|| {
            AlgoError::Ledger {
                message: format!("make_genesis_block: unknown protocol '{}'", genesis.proto),
            }
        })?;
    let gh = genesis_hash(genesis);
    let fee_sink = Address::from_algorand_string(&genesis.fees)?;
    let rewards_pool = Address::from_algorand_string(&genesis.rwd)?;
    let genesis_id = format!("{}-{}", genesis.network, genesis.id);

    // Rewards rate: go's MakeGenesisBlock divides the rewards-pool balance by
    // the refresh interval, subtracting MinBalance first under
    // InitialRewardsRateCalculation (v26+).
    let refresh = params.rewards_rate_refresh_interval;
    let rewards_pool_balance = genesis
        .alloc
        .iter()
        .find(|a| a.addr == genesis.rwd)
        .map(|a| a.state.algo)
        .unwrap_or(0);
    let initial_rewards = if params.initial_rewards_rate_calculation {
        rewards_pool_balance.saturating_sub(params.min_balance)
    } else {
        rewards_pool_balance
    };
    let rewards_rate = initial_rewards.checked_div(refresh).unwrap_or_default();

    Ok(algo_types::Block {
        round: algo_types::Round(0),
        branch: [0u8; 32],
        seed: gh, // committee.Seed(genesisHash)
        timestamp: genesis.timestamp,
        genesis_id,
        genesis_hash: if params.support_genesis_hash {
            gh
        } else {
            [0u8; 32]
        },
        fee_sink,
        rewards_pool,
        rewards_level: 0,
        rewards_rate,
        rewards_residue: 0,
        rewards_recalculation_round: algo_types::Round(refresh),
        current_protocol: genesis.proto.clone(),
        // AppForbidLowResources (v38+): bump TxnCounter so the first
        // created asset/app gets id 1001, not id 1 (see doc comment).
        txn_counter: if params.app_forbid_low_resources {
            1000
        } else {
            0
        },
        txn_commitment: GENESIS_EMPTY_PAYSET_COMMITMENT,
        ..Default::default()
    })
}

/// go's real commitment to an empty *non-nil* payset at genesis:
/// `SHA512_256("PF" ++ msgpack([]))` == `bookkeeping.Payset{}.CommitGenesis()`
/// (`../go-algorand/data/transactions/payset.go` @ v4.6.0-stable). The
/// genesis block is the only block that commits to an empty-but-non-nil
/// payset — every other empty block commits to the nil-payset digest
/// instead (go's `commit(genesis bool)` treats the two paysets
/// differently only at genesis). Verified against go's own test fixture
/// `emptyFlatPaysetHash` in `payset_test.go`.
const GENESIS_EMPTY_PAYSET_COMMITMENT: [u8; 32] = [
    0x27, 0x78, 0x62, 0xb1, 0xb2, 0xd2, 0xd1, 0x27, 0x9b, 0xb5, 0xa1, 0x9d, 0x0d, 0x87, 0x51, 0x8f,
    0xe7, 0x15, 0x00, 0xf1, 0x26, 0xb8, 0xba, 0x33, 0x67, 0x75, 0xbd, 0x34, 0x9a, 0x1e, 0x7b, 0x73,
];

/// Encode a single `GenesisAllocation` as a msgpack map.
///
/// IMPORTANT: addr, comment, and state are ALWAYS emitted — Go's
/// `genesis.go:155-164` notes "we forgot to specify omitempty"
/// for this type. So even an empty `comment` lands as a 0-length
/// string in the msgpack output (which matters because mainnet has
/// allocations with `"comment": ""`).
fn encode_allocation(a: &GenesisAllocation) -> Vec<u8> {
    let mut out = Vec::new();
    rmp::encode::write_map_len(&mut out, 3).unwrap();

    rmp::encode::write_str(&mut out, "addr").unwrap();
    out.extend_from_slice(&encode_str(&a.addr));

    rmp::encode::write_str(&mut out, "comment").unwrap();
    let comment = a.comment.as_deref().unwrap_or("");
    out.extend_from_slice(&encode_str(comment));

    rmp::encode::write_str(&mut out, "state").unwrap();
    out.extend_from_slice(&encode_account_state(&a.state));

    out
}

/// Encode a `GenesisAccountState` as a canonical msgpack map.
/// `GenesisAccountData` in Go has the standard
/// `omitempty,omitemptyarray` semantics — every field skips when
/// zero-valued.
///
/// Go field order (canonical, sorted): algo, onl, sel, stprf, vote,
/// voteFst, voteKD, voteLst.
fn encode_account_state(s: &GenesisAccountState) -> Vec<u8> {
    let mut fields: Vec<(&'static str, Vec<u8>)> = Vec::new();

    if s.algo != 0 {
        let mut buf = Vec::new();
        rmp::encode::write_uint(&mut buf, s.algo).unwrap();
        fields.push(("algo", buf));
    }
    if let Some(v) = s.onl {
        if v != 0 {
            let mut buf = Vec::new();
            rmp::encode::write_uint(&mut buf, v as u64).unwrap();
            fields.push(("onl", buf));
        }
    }
    if let Some(b) = decode_b64_nonempty(&s.sel) {
        fields.push(("sel", encode_bin(&b)));
    }
    if let Some(b) = decode_b64_nonempty(&s.stprf) {
        fields.push(("stprf", encode_bin(&b)));
    }
    if let Some(b) = decode_b64_nonempty(&s.vote) {
        fields.push(("vote", encode_bin(&b)));
    }
    if let Some(v) = s.vote_fst {
        if v != 0 {
            let mut buf = Vec::new();
            rmp::encode::write_uint(&mut buf, v).unwrap();
            fields.push(("voteFst", buf));
        }
    }
    if let Some(v) = s.vote_kd {
        if v != 0 {
            let mut buf = Vec::new();
            rmp::encode::write_uint(&mut buf, v).unwrap();
            fields.push(("voteKD", buf));
        }
    }
    if let Some(v) = s.vote_lst {
        if v != 0 {
            let mut buf = Vec::new();
            rmp::encode::write_uint(&mut buf, v).unwrap();
            fields.push(("voteLst", buf));
        }
    }

    fields.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    let mut out = Vec::new();
    rmp::encode::write_map_len(&mut out, fields.len() as u32).unwrap();
    for (k, v) in fields {
        rmp::encode::write_str(&mut out, k).unwrap();
        out.extend_from_slice(&v);
    }
    out
}

fn encode_str(s: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    rmp::encode::write_str(&mut buf, s).unwrap();
    buf
}

fn encode_bin(b: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    rmp::encode::write_bin(&mut buf, b).unwrap();
    buf
}

/// Encode a signed i64 using msgpack's positive-fixint / uint / int
/// rules, matching go-codec's "shortest signed" output. Positive
/// values go through the unsigned path because that's how Go's
/// reflective encoder writes non-negative ints with omitempty (a
/// positive Timestamp lands as a uint, not an int).
fn encode_i64(buf: &mut Vec<u8>, v: i64) {
    if v >= 0 {
        rmp::encode::write_uint(buf, v as u64).unwrap();
    } else {
        rmp::encode::write_sint(buf, v).unwrap();
    }
}

/// Decode an optional base64 string into bytes, returning `None`
/// for absent / empty / all-zero values (matches Go's omitempty for
/// fixed-size byte arrays).
fn decode_b64_nonempty(value: &Option<String>) -> Option<Vec<u8>> {
    let s = value.as_ref()?;
    if s.is_empty() {
        return None;
    }
    let bytes = BASE64.decode(s.as_bytes()).ok()?;
    if bytes.iter().all(|&b| b == 0) {
        None
    } else {
        Some(bytes)
    }
}

/// Seed the SQLite ledger's `accounttotals` table from a parsed genesis.
///
/// PLAN-32 / TASK-95 — a brand-new ledger has no `accounttotals` row at
/// all until something writes one, so `Certificate::authenticate`'s
/// `circulation()` lookup would return 0 and verification would fail at
/// genesis. This sums allocation `algo` amounts by online/offline/
/// not-participating status and writes the round-0 baseline row.
///
/// As of issue #523, `apply_block` incrementally maintains this row on
/// every subsequent block (`SqliteLedger::set_account`/`remove_account`
/// accumulate a per-block delta, flushed in `commit_block` — mirrors
/// go-algorand's `roundCowState.CalculateTotals`, `ledger/eval/cow.go`),
/// so this seed only needs to be correct at round 0; it is no longer the
/// sole source of truth for a long-running node. `catchpoint::importer`
/// remains the authoritative writer for a catchpoint-imported ledger
/// (which skips genesis entirely).
pub fn seed_account_totals_from_genesis(
    ledger: &mut crate::sqlite::SqliteLedger,
    genesis: &GenesisJson,
) -> Result<(), AlgoError> {
    use std::collections::HashMap;

    // Deduplicate by address — populate_store is last-write-wins per
    // address, so a duplicate allocation would otherwise double-count
    // here and diverge accounttotals from what actually lives in
    // accountbase. Sample genesis files (e.g. fee sink + rewards pool
    // sharing the reserve address) hit this in practice.
    let mut per_addr: HashMap<String, (AccountStatus, u64)> = HashMap::new();
    for alloc in &genesis.alloc {
        let status = effective_genesis_status(&alloc.addr, &alloc.state, &genesis.fees);
        per_addr.insert(alloc.addr.clone(), (status, alloc.state.algo));
    }
    // Reward units per account are floor(microAlgos / RewardUnit), summed by
    // status — go's `AccountTotals` (`AlgoCount.RewardUnits`). The per-account
    // floor means the sum differs from total_money / RewardUnit, so it must be
    // accumulated per account, not derived from the status totals. These feed
    // the per-round rewards-level advance (`next_rewards_state`).
    //
    // RewardUnit is a fixed 1e6 microAlgos across every consensus version (go
    // documents it must never change), so use the crate constant rather than a
    // protocol lookup — consistent with `compute_pending_rewards`, and it avoids
    // erroring on the placeholder protocols used in some genesis fixtures.
    let reward_unit = crate::rewards::REWARD_UNITS;

    let mut online: u64 = 0;
    let mut offline: u64 = 0;
    let mut not_participating: u64 = 0;
    let mut online_ru: u64 = 0;
    let mut offline_ru: u64 = 0;
    let mut not_participating_ru: u64 = 0;
    for (_, (status, algo)) in per_addr {
        let ru = algo / reward_unit;
        match status {
            AccountStatus::Online => {
                online = online.saturating_add(algo);
                online_ru = online_ru.saturating_add(ru);
            }
            AccountStatus::Offline => {
                offline = offline.saturating_add(algo);
                offline_ru = offline_ru.saturating_add(ru);
            }
            AccountStatus::NotParticipating => {
                not_participating = not_participating.saturating_add(algo);
                not_participating_ru = not_participating_ru.saturating_add(ru);
            }
        }
    }
    ledger.put_account_totals_seed(
        online,
        online_ru,
        offline,
        offline_ru,
        not_participating,
        not_participating_ru,
    )?;
    // Issue #523: `populate_store` above ran through `LedgerStore::set_account`
    // for every allocation, which (as of #523's fix) accumulates a
    // per-block `accounttotals` delta reflecting those same writes. The
    // seed row just written already sums genesis allocations directly and
    // is authoritative — flushing the accumulated delta on top at the next
    // `commit_block` would double-count the whole genesis supply. Discard
    // it now that the seed has superseded it.
    ledger.discard_pending_account_totals_delta();
    Ok(())
}

impl LedgerState {
    /// Load ledger state from a genesis.json file on disk.
    pub fn from_genesis(path: &Path) -> Result<LedgerState, AlgoError> {
        let json_str = std::fs::read_to_string(path).map_err(|e| AlgoError::Ledger {
            message: format!("failed to read genesis file {}: {e}", path.display()),
        })?;
        Self::from_genesis_json(&json_str)
    }

    /// Parse a genesis JSON string and build the initial ledger state.
    ///
    /// Populates accounts from allocations, sets fee_sink, rewards_pool,
    /// genesis_id, and protocol version.
    pub fn from_genesis_json(json_str: &str) -> Result<LedgerState, AlgoError> {
        let genesis = parse_genesis_json(json_str)?;
        let mut state = LedgerState::new();
        populate_store(&mut state, &genesis)?;
        Ok(state)
    }
}

/// Decode an optional base64 string into a 32-byte key.
fn decode_key_32(value: &Option<String>, field_name: &str) -> Result<Option<[u8; 32]>, AlgoError> {
    match value {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => {
            let bytes = BASE64.decode(s.as_bytes()).map_err(|e| AlgoError::Ledger {
                message: format!("invalid base64 for {field_name}: {e}"),
            })?;
            let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| AlgoError::Ledger {
                message: format!("{field_name}: expected 32 bytes, got {}", v.len()),
            })?;
            Ok(Some(arr))
        }
    }
}

/// Decode an optional base64 string into a 64-byte key (state proof key).
fn decode_key_64(value: &Option<String>, field_name: &str) -> Result<Option<[u8; 64]>, AlgoError> {
    match value {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => {
            let bytes = BASE64.decode(s.as_bytes()).map_err(|e| AlgoError::Ledger {
                message: format!("invalid base64 for {field_name}: {e}"),
            })?;
            let arr: [u8; 64] = bytes.try_into().map_err(|v: Vec<u8>| AlgoError::Ledger {
                message: format!("{field_name}: expected 64 bytes, got {}", v.len()),
            })?;
            Ok(Some(arr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE32_NOPAD;
    use std::path::PathBuf;

    /// Locate a go-algorand genesis fixture relative to this workspace.
    /// Returns `None` when the sibling `../go-algorand` checkout isn't
    /// present (CI may run without it; the test then skips rather
    /// than fails). CLAUDE.md documents the layout: go-algorand is
    /// pinned at `../go-algorand`.
    fn go_algorand_genesis_path(network: &str) -> Option<PathBuf> {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
        let p = PathBuf::from(manifest)
            .join("../../../../go-algorand/installer/genesis")
            .join(network)
            .join("genesis.json");
        p.exists().then_some(p)
    }

    fn b32_digest(d: &[u8; 32]) -> String {
        BASE32_NOPAD.encode(d)
    }

    const SAMPLE_GENESIS: &str = r#"{
        "network": "testnet",
        "id": "v1.0",
        "proto": "https://github.com/algorandfoundation/specs/tree/44fa607d6051730f5264526bf3c108d51f0eadb6",
        "alloc": [
            {
                "addr": "7777777777777777777777777777777777777777777777777774MSJUVU",
                "comment": "FeeSink",
                "state": { "algo": 100000 }
            },
            {
                "addr": "7777777777777777777777777777777777777777777777777774MSJUVU",
                "comment": "RewardsPool",
                "state": { "algo": 5000000000 }
            }
        ],
        "fees": "7777777777777777777777777777777777777777777777777774MSJUVU",
        "rwd": "7777777777777777777777777777777777777777777777777774MSJUVU"
    }"#;

    #[test]
    fn test_parse_genesis_json() {
        let state = LedgerState::from_genesis_json(SAMPLE_GENESIS).unwrap();
        assert_eq!(state.genesis_id, "testnet-v1.0"); // "testnet" + "-" + "v1.0"
        assert!(!state.fee_sink.is_zero());
        assert!(!state.rewards_pool.is_zero());
        // Last allocation wins (same address written twice)
        assert_eq!(state.accounts.len(), 1);
        // G7: populate_store now computes the genesis hash; it must
        // be non-zero and stable across two invocations with the
        // same input.
        assert_ne!(state.genesis_hash, [0u8; 32]);
        let second = LedgerState::from_genesis_json(SAMPLE_GENESIS).unwrap();
        assert_eq!(state.genesis_hash, second.genesis_hash);
    }

    #[test]
    fn test_parse_genesis_with_online_account() {
        let json = r#"{
            "network": "devnet",
            "id": "v1.0",
            "proto": "test-proto",
            "alloc": [
                {
                    "addr": "7777777777777777777777777777777777777777777777777774MSJUVU",
                    "comment": "Online validator",
                    "state": {
                        "algo": 1000000,
                        "onl": 1,
                        "voteFst": 1,
                        "voteLst": 3000000,
                        "voteKD": 10000
                    }
                }
            ],
            "fees": "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU",
            "rwd": "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU"
        }"#;

        let state = LedgerState::from_genesis_json(json).unwrap();
        let addr = Address::from_algorand_string(
            "7777777777777777777777777777777777777777777777777774MSJUVU",
        )
        .unwrap();
        let account = state.get_account(&addr).unwrap();
        // The allocation address is distinct from the fee sink / rewards
        // pool placeholder above, so `effective_genesis_status` doesn't force
        // it to NotParticipating — the declared `"onl": 1` applies as-is.
        assert_eq!(account.status, AccountStatus::Online);
        assert_eq!(account.micro_algos, 1_000_000);
        assert_eq!(account.vote_first_valid, 1);
        assert_eq!(account.vote_last_valid, 3_000_000);
        assert_eq!(account.vote_key_dilution, 10_000);
    }

    /// Live-verified against go-algorand v4.6.0-stable (issue #129): the fee
    /// sink is always reported `NotParticipating`, even when the genesis
    /// file's own `"onl"` field for it says `0` (Offline) -- but the
    /// **rewards pool** honors its declared status like any other account.
    /// Directly asserted on `populate_store`'s output (the account status
    /// `/v2/accounts/{address}` reports) here; the corresponding
    /// `/v2/ledger/supply` effect is covered by
    /// `seed_account_totals_from_genesis_sums_by_status` and the
    /// dedicated `seed_account_totals_excludes_fee_sink_only` test below.
    ///
    /// See [`effective_genesis_status`]'s doc comment for why an earlier
    /// version of this test (and the code it covers) also forced the
    /// rewards pool to `NotParticipating`: that claim came from a
    /// zero-balance rewards pool, which made "Offline" and
    /// "NotParticipating" observationally identical. This test now uses a
    /// nonzero rewards-pool balance specifically so the two are
    /// distinguishable, matching the live-verified go-algorand v4.6.0-stable
    /// behavior (issue #449).
    #[test]
    fn fee_sink_forced_not_participating_rewards_pool_honors_declared_status() {
        let json = r#"{
            "network": "devnet",
            "id": "v1.0",
            "proto": "test-proto",
            "alloc": [
                {
                    "addr": "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU",
                    "comment": "FeeSink",
                    "state": { "algo": 100000, "onl": 0 }
                },
                {
                    "addr": "TJD47PJE4JPJV6W2RNS47KXA2IID52Y2S5OPUSXKJZLWSEWMNJ4R2GIOFM",
                    "comment": "RewardsPool",
                    "state": { "algo": 125000000000000, "onl": 0 }
                }
            ],
            "fees": "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU",
            "rwd": "TJD47PJE4JPJV6W2RNS47KXA2IID52Y2S5OPUSXKJZLWSEWMNJ4R2GIOFM"
        }"#;

        let state = LedgerState::from_genesis_json(json).unwrap();
        let fee_sink_addr = Address::from_algorand_string(
            "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU",
        )
        .unwrap();
        let rewards_pool_addr = Address::from_algorand_string(
            "TJD47PJE4JPJV6W2RNS47KXA2IID52Y2S5OPUSXKJZLWSEWMNJ4R2GIOFM",
        )
        .unwrap();
        assert_eq!(
            state.get_account(&fee_sink_addr).unwrap().status,
            AccountStatus::NotParticipating,
            "fee sink must be NotParticipating regardless of the genesis file's onl:0"
        );
        assert_eq!(
            state.get_account(&rewards_pool_addr).unwrap().status,
            AccountStatus::Offline,
            "rewards pool must honor the genesis file's declared onl:0 (Offline), not be force-overridden"
        );
    }

    /// The `/v2/ledger/supply` companion to the test above: a fee sink
    /// funded in genesis must not count toward `total-money`
    /// (`participating_money` / go's `AccountTotals.Participating()`,
    /// `Online.Money + Offline.Money`) even though its own `"onl"` field
    /// says Offline — matching the `total-money` mismatch found live
    /// against go-algorand (issue #129). The rewards pool, by contrast,
    /// *does* count (issue #449 -- see `effective_genesis_status`'s doc
    /// comment).
    #[test]
    fn seed_account_totals_excludes_fee_sink_only() {
        let json = r#"{
            "network": "devnet",
            "id": "v1.0",
            "proto": "test-proto",
            "alloc": [
                {
                    "addr": "GBMUQUM7E3QW75GCVLQFMCS2Y7V5XTOJUBRVBXWOLS3EENBZP4AIGPHM6A",
                    "comment": "dev account",
                    "state": { "algo": 1000, "onl": 0 }
                },
                {
                    "addr": "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU",
                    "comment": "FeeSink",
                    "state": { "algo": 100000, "onl": 0 }
                },
                {
                    "addr": "TJD47PJE4JPJV6W2RNS47KXA2IID52Y2S5OPUSXKJZLWSEWMNJ4R2GIOFM",
                    "comment": "RewardsPool",
                    "state": { "algo": 500, "onl": 0 }
                }
            ],
            "fees": "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU",
            "rwd": "TJD47PJE4JPJV6W2RNS47KXA2IID52Y2S5OPUSXKJZLWSEWMNJ4R2GIOFM"
        }"#;
        let genesis = parse_genesis_json(json).unwrap();
        let mut ledger = crate::sqlite::SqliteLedger::open_in_memory().unwrap();
        seed_account_totals_from_genesis(&mut ledger, &genesis).unwrap();
        // The 1000-microAlgo dev account and the 500-microAlgo rewards pool
        // (both Offline) are participating; the fee sink's 100000 is
        // excluded.
        assert_eq!(ledger.participating_money().unwrap(), 1500);
    }

    #[test]
    fn test_invalid_genesis_json() {
        let result = LedgerState::from_genesis_json("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn seed_account_totals_from_genesis_sums_by_status() {
        // PLAN-32 / TASK-95: regression test for the harness-style genesis
        // seeder — 2 online + 1 offline + 1 not-participating allocation
        // should land as three distinct totals in accounttotals.
        let json = r#"{
            "network": "phase6net",
            "id": "v1",
            "proto": "future",
            "alloc": [
                {"addr": "A2UDRUOIEWEYDTE5DJLC4EH2HWFKQMZOPUKGNOWDOJOLJFPOPZ4EVXAAJY",
                 "comment": "online-1",
                 "state": {"algo": 33, "onl": 1}},
                {"addr": "GBMUQUM7E3QW75GCVLQFMCS2Y7V5XTOJUBRVBXWOLS3EENBZP4AIGPHM6A",
                 "comment": "online-2",
                 "state": {"algo": 33, "onl": 1}},
                {"addr": "ALGORANDSCOLLECTSFEES7777777777777777777777777777777746MSJUVU",
                 "comment": "offline",
                 "state": {"algo": 33, "onl": 0}},
                {"addr": "B2UDRUOIEWEYDTE5DJLC4EH2HWFKQMZOPUKGNOWDOJOLJFPOPZ4EVXAAJY",
                 "comment": "notpart",
                 "state": {"algo": 1, "onl": 2}}
            ],
            "fees": "7777777777777777777777777777777777777777777777777774MSJUVU",
            "rwd":  "7777777777777777777777777777777777777777777777777774MSJUVU"
        }"#;
        let genesis = parse_genesis_json(json).unwrap();
        let mut ledger = crate::sqlite::SqliteLedger::open_in_memory().unwrap();
        seed_account_totals_from_genesis(&mut ledger, &genesis).unwrap();
        // Total online = 33 + 33 = 66; online_stake reads that column.
        assert_eq!(ledger.online_stake().unwrap(), 66);
    }

    #[test]
    fn seed_account_totals_from_genesis_seeds_reward_units() {
        // TASK-276: per-status reward units = sum of per-account
        // floor(microAlgos / RewardUnit). total_reward_units() returns
        // online + offline (NotParticipating excluded), feeding the rewards
        // advance. The per-account floor is why 2.5 RU contributes 2, not the
        // status total / RewardUnit.
        let ru = algo_types::consensus::consensus_params_for_version("future")
            .unwrap()
            .reward_unit;
        assert!(ru > 0);
        let json = format!(
            r#"{{
            "network": "phase6net",
            "id": "v1",
            "proto": "future",
            "alloc": [
                {{"addr": "A2UDRUOIEWEYDTE5DJLC4EH2HWFKQMZOPUKGNOWDOJOLJFPOPZ4EVXAAJY",
                 "comment": "online-5ru", "state": {{"algo": {}, "onl": 1}}}},
                {{"addr": "GBMUQUM7E3QW75GCVLQFMCS2Y7V5XTOJUBRVBXWOLS3EENBZP4AIGPHM6A",
                 "comment": "online-2ru", "state": {{"algo": {}, "onl": 1}}}},
                {{"addr": "ALGORANDSCOLLECTSFEES7777777777777777777777777777777746MSJUVU",
                 "comment": "offline-3ru", "state": {{"algo": {}, "onl": 0}}}},
                {{"addr": "B2UDRUOIEWEYDTE5DJLC4EH2HWFKQMZOPUKGNOWDOJOLJFPOPZ4EVXAAJY",
                 "comment": "notpart-9ru", "state": {{"algo": {}, "onl": 2}}}}
            ],
            "fees": "7777777777777777777777777777777777777777777777777774MSJUVU",
            "rwd":  "7777777777777777777777777777777777777777777777777774MSJUVU"
        }}"#,
            5 * ru,
            2 * ru + ru / 2, // floors to 2 reward units
            3 * ru,
            9 * ru,
        );
        let genesis = parse_genesis_json(&json).unwrap();
        let mut ledger = crate::sqlite::SqliteLedger::open_in_memory().unwrap();
        seed_account_totals_from_genesis(&mut ledger, &genesis).unwrap();
        // online (5 + 2) + offline (3) = 10; not-participating (9) excluded.
        assert_eq!(ledger.total_reward_units().unwrap(), 10);
    }

    #[test]
    fn seed_account_totals_dedupes_duplicate_addrs() {
        // A genesis with the same address listed twice (e.g. fee sink
        // and rewards pool sharing the reserve) should match
        // populate_store's last-write-wins behavior — totals count
        // that address ONCE using the final status + amount, not the
        // sum of every row.
        let json = r#"{
            "network": "n", "id": "v", "proto": "p",
            "alloc": [
                {"addr": "7777777777777777777777777777777777777777777777777774MSJUVU",
                 "comment": "first",
                 "state": {"algo": 100, "onl": 1}},
                {"addr": "7777777777777777777777777777777777777777777777777774MSJUVU",
                 "comment": "second (wins)",
                 "state": {"algo": 50, "onl": 0}}
            ],
            "fees": "7777777777777777777777777777777777777777777777777774MSJUVU",
            "rwd":  "7777777777777777777777777777777777777777777777777774MSJUVU"
        }"#;
        let genesis = parse_genesis_json(json).unwrap();
        let mut ledger = crate::sqlite::SqliteLedger::open_in_memory().unwrap();
        seed_account_totals_from_genesis(&mut ledger, &genesis).unwrap();
        // Second entry (offline, 50) wins — online total is 0, not 100.
        assert_eq!(ledger.online_stake().unwrap(), 0);
    }

    #[test]
    fn has_account_totals_distinguishes_zero_online_from_unseeded() {
        // A network with zero online stake (everyone offline) is still
        // "seeded" once the accounttotals row has been written. The
        // relay bootstrap must not re-seed every restart for such
        // networks. Regression from Codex round-2 MEDIUM finding.
        let genesis = parse_genesis_json(
            r#"{"network":"n","id":"v","proto":"p","alloc":[
                {"addr":"7777777777777777777777777777777777777777777777777774MSJUVU",
                 "state":{"algo":100,"onl":0}}
            ],"fees":"7777777777777777777777777777777777777777777777777774MSJUVU",
              "rwd":"7777777777777777777777777777777777777777777777777774MSJUVU"}"#,
        )
        .unwrap();
        let mut ledger = crate::sqlite::SqliteLedger::open_in_memory().unwrap();
        assert!(
            !ledger.has_account_totals().unwrap(),
            "fresh ledger has no row"
        );
        seed_account_totals_from_genesis(&mut ledger, &genesis).unwrap();
        assert!(
            ledger.has_account_totals().unwrap(),
            "post-seed: accounttotals row present even with online==0"
        );
        assert_eq!(ledger.online_stake().unwrap(), 0);
    }

    #[test]
    fn seed_account_totals_is_idempotent() {
        // Calling twice should not double-count — INSERT OR REPLACE.
        let genesis = parse_genesis_json(
            r#"{"network":"n","id":"v","proto":"p","alloc":[
                {"addr":"7777777777777777777777777777777777777777777777777774MSJUVU",
                 "state":{"algo":10,"onl":1}}
            ],"fees":"GBMUQUM7E3QW75GCVLQFMCS2Y7V5XTOJUBRVBXWOLS3EENBZP4AIGPHM6A",
              "rwd":"GBMUQUM7E3QW75GCVLQFMCS2Y7V5XTOJUBRVBXWOLS3EENBZP4AIGPHM6A"}"#,
        )
        .unwrap();
        let mut ledger = crate::sqlite::SqliteLedger::open_in_memory().unwrap();
        seed_account_totals_from_genesis(&mut ledger, &genesis).unwrap();
        seed_account_totals_from_genesis(&mut ledger, &genesis).unwrap();
        assert_eq!(ledger.online_stake().unwrap(), 10);
    }

    // -----------------------------------------------------------------
    // G7: genesis hash parity with Go
    // -----------------------------------------------------------------

    /// Pin the four shipped networks' expected hashes from
    /// `../go-algorand/installer/genesis/<net>/genesis.json.hash`.
    /// If these strings ever change, either Go shipped a new genesis
    /// (compare against the pinned `v4.6.0-stable` tree) or Rust is
    /// silently breaking hash parity.
    #[test]
    fn genesis_hash_matches_go_for_mainnet() {
        check_network_hash(
            "mainnet",
            // ../go-algorand/installer/genesis/mainnet/genesis.json.hash
            "YBQ4JWH4DW655UWXMBF6IVUOH5WQIGMHVQ333ZFWEC22WOJERLPQ",
        );
    }

    #[test]
    fn genesis_hash_matches_go_for_testnet() {
        check_network_hash(
            "testnet",
            // ../go-algorand/installer/genesis/testnet/genesis.json.hash
            read_pinned_hash("testnet").as_str(),
        );
    }

    #[test]
    fn genesis_hash_matches_go_for_devnet() {
        check_network_hash("devnet", read_pinned_hash("devnet").as_str());
    }

    #[test]
    fn genesis_hash_matches_go_for_betanet() {
        check_network_hash("betanet", read_pinned_hash("betanet").as_str());
    }

    /// Read the base32 hash string from
    /// `../go-algorand/installer/genesis/<net>/genesis.json.hash`,
    /// returning an empty string if the file is unavailable (the
    /// caller's `check_network_hash` then skips with a warning).
    fn read_pinned_hash(network: &str) -> String {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        let p = PathBuf::from(manifest)
            .join("../../../../go-algorand/installer/genesis")
            .join(network)
            .join("genesis.json.hash");
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .trim()
            .to_string()
    }

    fn check_network_hash(network: &str, expected_b32: &str) {
        let Some(path) = go_algorand_genesis_path(network) else {
            eprintln!(
                "skipping genesis hash test for {network}: \
                 ../go-algorand/installer/genesis/{network}/genesis.json not found"
            );
            return;
        };
        if expected_b32.is_empty() {
            eprintln!(
                "skipping genesis hash test for {network}: \
                 genesis.json.hash sibling file is missing"
            );
            return;
        }

        let json = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let genesis =
            parse_genesis_json(&json).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        let h = genesis_hash(&genesis);
        let got_b32 = b32_digest(&h);

        assert_eq!(
            got_b32, expected_b32,
            "{network}: Rust genesis_hash differs from Go's pinned hash.\n  \
             expected: {expected_b32}\n  \
             got:      {got_b32}"
        );
    }

    #[test]
    fn canonical_encode_genesis_emits_sorted_keys_and_omits_empty() {
        // Sanity-check the canonical-encoding contract independent of
        // any pinned hash: a genesis with timestamp=0, comment="",
        // devmode=false must omit those fields, and the remaining keys
        // must appear in lexicographic order in the msgpack output.
        let genesis = GenesisJson {
            network: "n".to_string(),
            id: "v".to_string(),
            proto: "p".to_string(),
            alloc: vec![],
            fees: "7777777777777777777777777777777777777777777777777774MSJUVU".to_string(),
            rwd: "7777777777777777777777777777777777777777777777777774MSJUVU".to_string(),
            timestamp: 0,
            comment: None,
            devmode: false,
        };
        let bytes = canonical_encode_genesis(&genesis);

        // The keys present should be exactly: fees, id, network, proto, rwd.
        // (alloc is empty → omitted; timestamp=0 → omitted; comment empty
        // and devmode false → omitted.)
        let s = String::from_utf8_lossy(&bytes);
        for key in ["fees", "id", "network", "proto", "rwd"] {
            assert!(s.contains(key), "missing expected key `{key}`");
        }
        for key in ["alloc", "comment", "devmode", "timestamp"] {
            assert!(!s.contains(key), "key `{key}` should be omitted");
        }

        // Map header byte for a 5-entry map is fixmap(5) = 0x85.
        assert_eq!(bytes[0], 0x85);
    }

    #[test]
    fn canonical_encode_genesis_devmode_and_comment_round_trip() {
        // A genesis with devmode=true + comment="dev" + timestamp=42
        // must include all three in the canonical output. The
        // resulting hash is internally consistent — encoding the same
        // genesis twice yields the same bytes.
        let genesis = GenesisJson {
            network: "devnet".to_string(),
            id: "v1".to_string(),
            proto: "p".to_string(),
            alloc: vec![],
            fees: "7777777777777777777777777777777777777777777777777774MSJUVU".to_string(),
            rwd: "7777777777777777777777777777777777777777777777777774MSJUVU".to_string(),
            timestamp: 42,
            comment: Some("dev".to_string()),
            devmode: true,
        };
        let a = canonical_encode_genesis(&genesis);
        let b = canonical_encode_genesis(&genesis);
        assert_eq!(a, b, "canonical encoding must be deterministic");

        let s = String::from_utf8_lossy(&a);
        assert!(s.contains("comment"));
        assert!(s.contains("devmode"));
        assert!(s.contains("timestamp"));
    }
}

#[cfg(test)]
mod genesis_block_tests {
    use super::*;

    fn test_genesis() -> GenesisJson {
        let fees = Address([0xFE; 32]).to_algorand_string();
        let rwd = Address([0xFD; 32]).to_algorand_string();
        let json = format!(
            r#"{{"id":"v1","network":"localnet","proto":"future","fees":"{fees}","rwd":"{rwd}","timestamp":0,"alloc":[{{"addr":"{rwd}","comment":"RewardsPool","state":{{"algo":1000000000000,"onl":0}}}}]}}"#
        );
        parse_genesis_json(&json).unwrap()
    }

    #[test]
    fn make_genesis_block_rejects_unknown_protocol_gracefully() {
        // Regression test for issue #676: a well-formed but unrecognized
        // future consensus-version string (e.g. a not-yet-modeled upstream
        // named version, such as a hypothetical `fnetN` before it was added
        // to `consensus_params_for_version`) must produce a proper
        // `AlgoError`, never a panic, at genesis load.
        let fees = Address([0xFE; 32]).to_algorand_string();
        let rwd = Address([0xFD; 32]).to_algorand_string();
        let json = format!(
            r#"{{"id":"v1","network":"localnet","proto":"future-vNEXT-unrecognized","fees":"{fees}","rwd":"{rwd}","timestamp":0,"alloc":[{{"addr":"{rwd}","comment":"RewardsPool","state":{{"algo":1000000000000,"onl":0}}}}]}}"#
        );
        let g = parse_genesis_json(&json).unwrap();
        let result = make_genesis_block(&g);
        assert!(result.is_err(), "unknown protocol must error, not panic");
    }

    #[test]
    fn genesis_block_round_trips_through_codec() {
        let g = test_genesis();
        let blk = make_genesis_block(&g).unwrap();
        assert_eq!(blk.round, algo_types::Round(0));
        assert_eq!(blk.seed, genesis_hash(&g));
        assert_eq!(blk.current_protocol, "future");
        assert_eq!(blk.txn_counter, 1000);
        // Full block must round-trip through the codec the REST layer uses.
        let encoded = algo_codec::encode_block(&blk).expect("encode");
        let decoded = algo_codec::decode_block(&encoded).expect("decode full block");
        assert_eq!(decoded.round, blk.round);
        // Header must round-trip too (what get_block_header decodes).
        let hdr = algo_codec::canonical_encode_block_header_from_block(&blk);
        let dh = algo_types::BlockHeader::decode_from_reader(&mut hdr.as_slice())
            .expect("decode header");
        assert_eq!(dh.round, algo_types::Round(0));
    }

    /// Build a genesis JSON pinned to `proto` (a `CONSENSUS_V*` version
    /// string) instead of `"future"`, so version-gated genesis behavior
    /// (`InitialRewardsRateCalculation`, `AppForbidLowResources`) can be
    /// tested on both sides of their real activation boundary.
    fn test_genesis_for_proto(proto: &str) -> GenesisJson {
        let fees = Address([0xFE; 32]).to_algorand_string();
        let rwd = Address([0xFD; 32]).to_algorand_string();
        let json = format!(
            r#"{{"id":"v1","network":"localnet","proto":"{proto}","fees":"{fees}","rwd":"{rwd}","timestamp":0,"alloc":[{{"addr":"{rwd}","comment":"RewardsPool","state":{{"algo":1000000000000,"onl":0}}}}]}}"#
        );
        parse_genesis_json(&json).unwrap()
    }

    #[test]
    fn app_forbid_low_resources_txn_counter_activation_boundary() {
        // v37 (pre-fix): TxnCounter starts at 0, so the first created
        // asset/app would get id 1.
        let g37 = test_genesis_for_proto(algo_types::consensus::CONSENSUS_V37);
        let blk37 = make_genesis_block(&g37).unwrap();
        assert_eq!(
            blk37.txn_counter, 0,
            "pre-v38 genesis must not bump TxnCounter"
        );

        // v38 (post-fix): TxnCounter starts at 1000, so the first created
        // asset/app gets id 1001.
        let g38 = test_genesis_for_proto(algo_types::consensus::CONSENSUS_V38);
        let blk38 = make_genesis_block(&g38).unwrap();
        assert_eq!(
            blk38.txn_counter, 1000,
            "v38+ genesis must bump TxnCounter to 1000"
        );
    }

    #[test]
    fn initial_rewards_rate_calculation_activation_boundary() {
        let pool_balance = 1_000_000_000_000u64;

        // v25 (pre-fix): rate = poolBalance / refreshInterval (no MinBalance
        // subtraction).
        let g25 = test_genesis_for_proto(algo_types::consensus::CONSENSUS_V25);
        let params25 = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V25,
        )
        .unwrap();
        let blk25 = make_genesis_block(&g25).unwrap();
        let expected25 = pool_balance / params25.rewards_rate_refresh_interval;
        assert_eq!(
            blk25.rewards_rate, expected25,
            "pre-v26 genesis must not subtract MinBalance from the rewards rate"
        );

        // v26 (post-fix): rate = (poolBalance - MinBalance) / refreshInterval.
        let g26 = test_genesis_for_proto(algo_types::consensus::CONSENSUS_V26);
        let params26 = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V26,
        )
        .unwrap();
        let blk26 = make_genesis_block(&g26).unwrap();
        let expected26 =
            (pool_balance - params26.min_balance) / params26.rewards_rate_refresh_interval;
        assert_eq!(
            blk26.rewards_rate, expected26,
            "v26+ genesis must subtract MinBalance from the rewards rate"
        );
        assert_ne!(
            expected25, expected26,
            "sanity: the two formulas must actually differ for this test to be meaningful"
        );
    }
}
