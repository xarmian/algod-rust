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

// Comprehensive consensus parameters, mirroring go-algorand's
// `config.ConsensusParams` struct and `initConsensusProtocols()`.
//
// Values are derived from go-algorand v4.6.0-stable (config/consensus.go).
// Each version inherits from its predecessor and overrides specific fields,
// exactly matching the Go initialisation chain.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

// ── Global protocol parameters (not per-version) ──────────────────
/// Min time to wait for leader's credential (time to propagate one credential).
/// Matches go-algorand `Protocol.SmallLambda` = 2000ms.
pub const SMALL_LAMBDA: Duration = Duration::from_millis(2000);
/// Max time to wait for leader's proposal (time to propagate one block).
/// Matches go-algorand `Protocol.BigLambda` = 15000ms.
pub const BIG_LAMBDA: Duration = Duration::from_millis(15000);

// ── Protocol version constants ──────────────────────────────────────
// Mirrors go-algorand `protocol/consensus.go` at tag v4.6.0-stable.
// Only versions v7+ are listed; v0–v6 are deprecated.

pub const CONSENSUS_V7: &str = "v7";
pub const CONSENSUS_V8: &str = "v8";
pub const CONSENSUS_V9: &str = "v9";
pub const CONSENSUS_V10: &str = "v10";
pub const CONSENSUS_V11: &str = "v11";
pub const CONSENSUS_V12: &str = "v12";
pub const CONSENSUS_V13: &str =
    "https://github.com/algorand/spec/tree/0c8a9dc44d7368cc266d5407b79fb3311f4fc795";
pub const CONSENSUS_V14: &str =
    "https://github.com/algorand/spec/tree/2526b6ae062b4fe5e163e06e41e1d9b9219135a9";
pub const CONSENSUS_V15: &str =
    "https://github.com/algorand/spec/tree/a26ed78ed8f834e2b9ccb6eb7d3ee9f629a6e622";
pub const CONSENSUS_V16: &str =
    "https://github.com/algorand/spec/tree/22726c9dcd12d9cddce4a8bd7e8ccaa707f74101";
pub const CONSENSUS_V17: &str =
    "https://github.com/algorandfoundation/specs/tree/5615adc36bad610c7f165fa2967f4ecfa75125f0";
pub const CONSENSUS_V18: &str =
    "https://github.com/algorandfoundation/specs/tree/6c6bd668be0ab14098e51b37e806c509f7b7e31f";
pub const CONSENSUS_V19: &str =
    "https://github.com/algorandfoundation/specs/tree/0e196e82bfd6e327994bec373c4cc81bc878ef5c";
pub const CONSENSUS_V20: &str =
    "https://github.com/algorandfoundation/specs/tree/4a9db6a25595c6fd097cf9cc137cc83027787eaa";
pub const CONSENSUS_V21: &str =
    "https://github.com/algorandfoundation/specs/tree/8096e2df2da75c3339986317f9abe69d4fa86b4b";
pub const CONSENSUS_V22: &str =
    "https://github.com/algorandfoundation/specs/tree/57016b942f6d97e6d4c0688b373bb0a2fc85a1a2";
pub const CONSENSUS_V23: &str =
    "https://github.com/algorandfoundation/specs/tree/e5f565421d720c6f75cdd186f7098495caf9101f";
pub const CONSENSUS_V24: &str =
    "https://github.com/algorandfoundation/specs/tree/3a83c4c743f8b17adfd73944b4319c25722a6782";
pub const CONSENSUS_V25: &str =
    "https://github.com/algorandfoundation/specs/tree/bea19289bf41217d2c0af30522fa222ef1366466";
pub const CONSENSUS_V26: &str =
    "https://github.com/algorandfoundation/specs/tree/ac2255d586c4474d4ebcf3809acccb59b7ef34ff";
pub const CONSENSUS_V27: &str =
    "https://github.com/algorandfoundation/specs/tree/d050b3cade6d5c664df8bd729bf219f179812595";
pub const CONSENSUS_V28: &str =
    "https://github.com/algorandfoundation/specs/tree/65b4ab3266c52c56a0fa7d591754887d68faad0a";
pub const CONSENSUS_V29: &str =
    "https://github.com/algorandfoundation/specs/tree/abc54f79f9ad679d2d22f0fb9909fb005c16f8a1";
pub const CONSENSUS_V30: &str =
    "https://github.com/algorandfoundation/specs/tree/bc36005dbd776e6d1eaf0c560619bb183215645c";
pub const CONSENSUS_V31: &str =
    "https://github.com/algorandfoundation/specs/tree/85e6db1fdbdef00aa232c75199e10dc5fe9498f6";
pub const CONSENSUS_V32: &str =
    "https://github.com/algorandfoundation/specs/tree/d5ac876d7ede07367dbaa26e149aa42589aac1f7";
pub const CONSENSUS_V33: &str =
    "https://github.com/algorandfoundation/specs/tree/830a4e673148498cc7230a0d1ba1ed0a5471acc6";
pub const CONSENSUS_V34: &str =
    "https://github.com/algorandfoundation/specs/tree/2dd5435993f6f6d65691140f592ebca5ef19ffbd";
pub const CONSENSUS_V35: &str =
    "https://github.com/algorandfoundation/specs/tree/433d8e9a7274b6fca703d91213e05c7e6a589e69";
pub const CONSENSUS_V36: &str =
    "https://github.com/algorandfoundation/specs/tree/44fa607d6051730f5264526bf3c108d51f0eadb6";
pub const CONSENSUS_V37: &str =
    "https://github.com/algorandfoundation/specs/tree/1ac4dd1f85470e1fb36c8a65520e1313d7dfed5e";
pub const CONSENSUS_V38: &str =
    "https://github.com/algorandfoundation/specs/tree/abd3d4823c6f77349fc04c3af7b1e99fe4df699f";
pub const CONSENSUS_V39: &str =
    "https://github.com/algorandfoundation/specs/tree/925a46433742afb0b51bb939354bd907fa88bf95";
pub const CONSENSUS_V40: &str =
    "https://github.com/algorandfoundation/specs/tree/236dcc18c9c507d794813ab768e467ea42d1b4d9";
pub const CONSENSUS_V41: &str =
    "https://github.com/algorandfoundation/specs/tree/953304de35264fc3ef91bcd05c123242015eeaed";
pub const CONSENSUS_V42: &str =
    "https://github.com/algorandfoundation/specs/tree/268b63433a907455d439995bf916f6b296018f4f";
pub const CONSENSUS_FUTURE: &str = "future";
pub const CONSENSUS_ALPHA1: &str = "alpha1";
pub const CONSENSUS_ALPHA2: &str = "alpha2";
pub const CONSENSUS_ALPHA3: &str = "alpha3";
pub const CONSENSUS_ALPHA4: &str = "alpha4";
pub const CONSENSUS_ALPHA5: &str = "alpha5";

// ── FNet versions ────────────────────────────────────────────────
// go: protocol/consensus.go (v5.0.0-stable), `ConsensusVFnet1`..`ConsensusVFnet4`.
// A dedicated test-network series (AF's FNet), analogous to the vAlphaX
// series above. algod-rust does not target FNet as a network, but these are
// included for table-completeness/documentation parity with go-algorand.
pub const CONSENSUS_VFNET1: &str = "fnet1";
pub const CONSENSUS_VFNET2: &str = "fnet2";
pub const CONSENSUS_VFNET3: &str = "fnet3";
pub const CONSENSUS_VFNET4: &str = "fnet4";

/// The current (latest release) consensus version.
pub const CONSENSUS_CURRENT_VERSION: &str = CONSENSUS_V42;

/// All protocol version strings recognised by go-algorand v4.6.0-stable.
pub const KNOWN_PROTOCOL_VERSIONS: &[&str] = &[
    // Short-form versions (v7-v12)
    CONSENSUS_V7,
    CONSENSUS_V8,
    CONSENSUS_V9,
    CONSENSUS_V10,
    CONSENSUS_V11,
    CONSENSUS_V12,
    // Spec-URL versions (v13-v41)
    CONSENSUS_V13,
    CONSENSUS_V14,
    CONSENSUS_V15,
    CONSENSUS_V16,
    CONSENSUS_V17,
    CONSENSUS_V18,
    CONSENSUS_V19,
    CONSENSUS_V20,
    CONSENSUS_V21,
    CONSENSUS_V22,
    CONSENSUS_V23,
    CONSENSUS_V24,
    CONSENSUS_V25,
    CONSENSUS_V26,
    CONSENSUS_V27,
    CONSENSUS_V28,
    CONSENSUS_V29,
    CONSENSUS_V30,
    CONSENSUS_V31,
    CONSENSUS_V32,
    CONSENSUS_V33,
    CONSENSUS_V34,
    CONSENSUS_V35,
    CONSENSUS_V36,
    CONSENSUS_V37,
    CONSENSUS_V38,
    CONSENSUS_V39,
    CONSENSUS_V40,
    CONSENSUS_V41,
    CONSENSUS_V42,
    // Special versions
    CONSENSUS_FUTURE,
    CONSENSUS_ALPHA1,
    CONSENSUS_ALPHA2,
    CONSENSUS_ALPHA3,
    CONSENSUS_ALPHA4,
    CONSENSUS_ALPHA5,
    CONSENSUS_VFNET1,
    CONSENSUS_VFNET2,
    CONSENSUS_VFNET3,
    CONSENSUS_VFNET4,
];

// ── ConsensusParams ─────────────────────────────────────────────────

/// Comprehensive consensus parameters mirroring go-algorand's
/// `config.ConsensusParams`. All fields needed to replace hardcoded
/// constants across the Rust codebase are included.
///
/// Values are derived per-version from go-algorand `config/consensus.go`
/// at tag v4.6.0-stable.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsensusParams {
    // ── AVM / LogicSig ──────────────────────────────────────────
    /// Protocol's max AVM version (Go: `LogicSigVersion`).
    /// 0 means no TEAL support.
    pub logic_sig_version: u64,
    /// Max LogicSig program+args size in bytes (Go: `LogicSigMaxSize`).
    pub logic_sig_max_size: u64,
    /// Absolute hard cap on a single LogicSig program's byte length,
    /// independent of group pooling (Go: `MaxAbsoluteLogicSigProgramSize`,
    /// set to `LogicSigMaxSize` at v18, raised to 16000 at v40 alongside
    /// `EnableLogicSigSizePooling`). A LogicSig program longer than this is
    /// never well-formed, no matter how much of the group's pooled allowance
    /// is unused. Zero means LogicSigs are not yet supported.
    pub max_absolute_logic_sig_program_size: u64,
    /// Max LogicSig opcode cost budget (Go: `LogicSigMaxCost`).
    pub logic_sig_max_cost: u64,
    /// Per-app-call opcode budget (Go: `MaxAppProgramCost`).
    pub max_app_program_cost: u64,

    // ── Account economics ───────────────────────────────────────
    /// Minimum account balance in microAlgos (Go: `MinBalance`).
    pub min_balance: u64,
    /// Minimum transaction fee in microAlgos (Go: `MinTxnFee`).
    pub min_txn_fee: u64,

    // ── Transaction limits ──────────────────────────────────────
    /// Max rounds a txn is valid (Go: `MaxTxnLife`).
    pub max_txn_life: u64,
    /// Max note field size in bytes (Go: `MaxTxnNoteBytes`).
    pub max_txn_note_bytes: usize,
    /// Max group size (Go: `MaxTxGroupSize`).
    pub max_tx_group_size: usize,
    /// Max block payload bytes (Go: `MaxTxnBytesPerBlock`).
    pub max_txn_bytes_per_block: u64,
    /// Absolute hard cap on note field size in bytes, beyond which a
    /// transaction is not well-formed regardless of size-pricing fee paid
    /// (Go: `MaxAbsoluteTxnNoteBytes`, v42+). `MaxTxnNoteBytes` remains the
    /// free/soft cap; bytes between the soft and absolute cap are billable
    /// via `PerByteTxnSurcharge`.
    pub max_absolute_txn_note_bytes: usize,
    /// Absolute hard cap on extra app program pages, beyond which an app
    /// create/update is not well-formed (Go: `MaxAbsoluteExtraProgramPages`,
    /// v28+ at 3, raised to 7 at v42 alongside size-pricing fees).
    pub max_absolute_extra_program_pages: u32,
    /// Absolute hard cap on the summed length of ApplicationArgs, beyond
    /// which an app call is not well-formed regardless of size-pricing fee
    /// paid (Go: `MaxAbsoluteTotalArgLen`, v42+).
    pub max_absolute_total_arg_len: usize,
    /// Per-byte fee surcharge (fixed-point `basics.Micros`, 1_000_000 == one
    /// `MinTxnFee`) charged for txn/app-call/logicsig bytes beyond the old
    /// free/soft caps but within the new `MaxAbsolute*` hard caps (Go:
    /// `PerByteTxnSurcharge`, v42+). Zero means size pricing is disabled.
    pub per_byte_txn_surcharge: u64,

    // ── Feature flags ───────────────────────────────────────────
    /// Sum of fees in a group must exceed one MinTxnFee per txn (Go: `EnableFeePooling`, v28+).
    pub enable_fee_pooling: bool,
    /// Transaction groups supported (Go: `SupportTxGroups`, v18+).
    pub support_tx_groups: bool,
    /// Transaction leases supported (Go: `SupportTransactionLeases`, v18+).
    pub support_transaction_leases: bool,
    /// Lease exclusion fix (Go: `FixTransactionLeases`, v23+).
    pub fix_transaction_leases: bool,
    /// Account rekeying supported (Go: `SupportRekeying`, v24+).
    pub support_rekeying: bool,
    /// Heartbeat transactions enabled (Go: `Heartbeat`, v40+).
    pub enable_heartbeat: bool,
    /// AuthAddr must differ from Sender (Go: `EnforceAuthAddrSenderDiff`, v42+).
    pub enforce_auth_addr_sender_diff: bool,
    /// Enables header values (`Load`/`CongestionTax`) that track how full recent
    /// blocks are, and derive a congestion-tax fee adjustment from it (Go:
    /// `LoadTracking`, v42+ — go-algorand v4.7.0-beta introduced it future-only,
    /// `config/consensus.go`, PR #6548; moved onto the real v42 release by
    /// commit `88fe542f3`).
    pub load_tracking: bool,
    /// Apps may update their approval/clear programs to larger page-extended
    /// sizes without extra restriction (Go: `AppSizeUpdates`, v42+).
    pub app_size_updates: bool,
    /// Applications may be referenced by local-state ops (`app_local_get`,
    /// etc.) using foreign-app index 0 to mean "this app", matching the
    /// existing global-state convention (Go: `AllowZeroLocalAppRef`, v42+).
    pub allow_zero_local_app_ref: bool,
    /// Enables native Falcon-1024 transaction authorization for the `f1` PQ
    /// scheme (Go: `EnablePQSchemeFalcon1024`, v42+). Full PQ wire-type
    /// plumbing (`PQSchemeEnabled`/`PQSchemeFeeContribution`) is tracked by a
    /// companion PQ-signatures issue; this flag is the consensus gate only.
    pub enable_pq_scheme_falcon1024: bool,
    /// Switches committee-selection (sortition) weight computation from the
    /// hardware-double/Boost-C++ binomial CDF walk to a pure-software
    /// 128-bit float implementation (`sortition.SelectF128`), which is
    /// bit-identical across platforms. Not AVM-related — this gates the
    /// vote/credential-verification weight function used throughout
    /// consensus (see `algo-agreement`'s `UnauthenticatedCredential::verify`
    /// and `algo-consensus-crypto::sortition::select_f128`)
    /// (Go: `EnableSelectF128`, v42+).
    pub enable_select_f128: bool,
    /// LogicSig sizes pooled across a group (Go: `EnableLogicSigSizePooling`, v40+).
    pub enable_logicsig_size_pooling: bool,
    /// LogicSig costs pooled across a group (Go: `EnableLogicSigCostPooling`, v39+).
    pub enable_logicsig_cost_pooling: bool,
    /// App call costs pooled across a group (Go: `EnableAppCostPooling`, v30+).
    pub enable_app_cost_pooling: bool,
    /// Inner transaction count pooled across a group (Go: `EnableInnerTransactionPooling`, v31+).
    pub enable_inner_transaction_pooling: bool,
    /// Application support enabled (Go: `Application`, v24+).
    pub application: bool,
    /// Asset support enabled (Go: `Asset`, v18+).
    pub asset: bool,

    // ── Inner transactions ──────────────────────────────────────
    /// Max inner txns per app call (Go: `MaxInnerTransactions`).
    /// 0 means inner transactions disabled. With pooling, this is
    /// multiplied by MaxTxGroupSize and enforced over the whole group.
    pub max_inner_transactions: usize,
    /// Minimum AVM version for inner app calls (Go: `MinInnerApplVersion`).
    pub min_inner_appl_version: u64,

    // ── Application state ───────────────────────────────────────
    /// Max app key length (Go: `MaxAppKeyLen`).
    pub max_app_key_len: usize,
    /// Max app bytes value length (Go: `MaxAppBytesValueLen`).
    pub max_app_bytes_value_len: usize,
    /// Max sum of key + value lengths (Go: `MaxAppSumKeyValueLens`).
    pub max_app_sum_key_value_lens: usize,
    /// Max extra app program pages (Go: `MaxExtraAppProgramPages`).
    pub max_extra_app_program_pages: u32,
    /// Max app program length per page (Go: `MaxAppProgramLen`).
    pub max_app_program_len: usize,
    /// Max total app program length per page (Go: `MaxAppTotalProgramLen`).
    pub max_app_total_program_len: usize,
    /// Max global schema entries (Go: `MaxGlobalSchemaEntries`).
    pub max_global_schema_entries: u64,
    /// Max local schema entries (Go: `MaxLocalSchemaEntries`).
    pub max_local_schema_entries: u64,

    // ── Application args / references ───────────────────────────
    /// Max number of ApplicationArgs (Go: `MaxAppArgs`).
    pub max_app_args: usize,
    /// Max sum of arg lengths (Go: `MaxAppTotalArgLen`).
    pub max_app_total_arg_len: usize,
    /// Max accounts in ApplicationCall (Go: `MaxAppTxnAccounts`).
    pub max_app_txn_accounts: usize,
    /// Max foreign apps (Go: `MaxAppTxnForeignApps`).
    pub max_app_txn_foreign_apps: usize,
    /// Max foreign assets (Go: `MaxAppTxnForeignAssets`).
    pub max_app_txn_foreign_assets: usize,
    /// Max total references (Go: `MaxAppTotalTxnReferences`).
    pub max_app_total_txn_references: usize,
    /// Max references in txn.Access (Go: `MaxAppAccess`, v41+).
    pub max_app_access: usize,

    // ── Box storage ─────────────────────────────────────────────
    /// Max box size in bytes (Go: `MaxBoxSize`).
    pub max_box_size: u64,
    /// Bytes per box reference in I/O budget (Go: `BytesPerBoxReference`).
    pub bytes_per_box_reference: u64,
    /// Max box references per app call (Go: `MaxAppBoxReferences`).
    pub max_app_box_references: usize,
    /// Whether box ref names are validated early, at `wellFormed` time
    /// (Go: `EnableBoxRefNameError`, v38+). Before v38, an over-long box
    /// name in `tx.Boxes`/`tx.Access` was only ever caught later, deep in
    /// box-resolution logic; from v38 on it's rejected at well-formedness.
    pub enable_box_ref_name_error: bool,

    // ── Min balance economics ───────────────────────────────────
    /// Flat MBR for creating an app (Go: `AppFlatParamsMinBalance`).
    pub app_flat_params_min_balance: u64,
    /// Flat MBR for opting into an app (Go: `AppFlatOptInMinBalance`).
    pub app_flat_opt_in_min_balance: u64,
    /// MBR per schema entry (Go: `SchemaMinBalancePerEntry`).
    pub schema_min_balance_per_entry: u64,
    /// MBR per uint entry (Go: `SchemaUintMinBalance`).
    pub schema_uint_min_balance: u64,
    /// MBR per bytes entry (Go: `SchemaBytesMinBalance`).
    pub schema_bytes_min_balance: u64,
    /// Flat MBR per box (Go: `BoxFlatMinBalance`).
    pub box_flat_min_balance: u64,
    /// MBR per box byte (Go: `BoxByteMinBalance`).
    pub box_byte_min_balance: u64,
    /// Maximum allowed effective minimum balance (Go: `MaximumMinimumBalance`).
    /// 0 means no limit (v32+ removes the cap). Set to 100_100_000 in v24.
    pub maximum_minimum_balance: u64,

    // ── Asset parameters ────────────────────────────────────────
    /// Max assets per account (Go: `MaxAssetsPerAccount`). 0 = unlimited (v32+).
    pub max_assets_per_account: u32,

    // ── Logging ─────────────────────────────────────────────────
    /// Max size of a single log message (AVM `log` opcode limit: 1024 bytes).
    pub max_log_size: usize,
    /// Max number of log calls per app execution (AVM limit: 32).
    pub max_log_calls: usize,

    // ── Block header history ────────────────────────────────────
    /// Additional rounds beyond MaxTxnLife for smart contract lookback
    /// (Go: `DeeperBlockHeaderHistory`, v33+).
    pub deeper_block_header_history: u64,

    // ── Rewards ─────────────────────────────────────────────────
    /// Number of microAlgos per reward unit (Go: `RewardUnit`).
    /// Rewards are received by whole reward units; fractions do not receive rewards.
    pub reward_unit: u64,
    /// Rounds between reward rate recalculations (Go: `RewardsRateRefreshInterval`).
    pub rewards_rate_refresh_interval: u64,

    // ── Block-level ─────────────────────────────────────────────
    /// Maximum seconds between successive block timestamps (Go: `MaxTimestampIncrement`).
    pub max_timestamp_increment: i64,
    /// How payset is committed: 0=unsupported, 1=flat, 2=merkle (Go: `PaysetCommit`).
    pub payset_commit: u8,
    /// SHA-256 txn commitment header (Go: `EnableSHA256TxnCommitmentHeader`, v34+).
    pub enable_sha256_txn_commitment_header: bool,
    /// SHA-512 block hash header (Go: `EnableSha512BlockHash`, v41+).
    pub enable_sha512_block_hash: bool,

    // ── Genesis / protocol ──────────────────────────────────────
    /// Require GenesisHash in every transaction (Go: `RequireGenesisHash`, v16+).
    pub require_genesis_hash: bool,
    /// Support GenesisHash field (Go: `SupportGenesisHash`, v14+).
    pub support_genesis_hash: bool,

    // ── Max app counts (0 = unlimited) ──────────────────────────
    /// Max apps an account can create (Go: `MaxAppsCreated`). 0 = unlimited (v32+).
    pub max_apps_created: usize,
    /// Max apps an account can opt into (Go: `MaxAppsOptedIn`). 0 = unlimited (v32+).
    pub max_apps_opted_in: usize,

    // ── Keyreg ──────────────────────────────────────────────────
    /// Max validity period for keyreg (Go: `MaxKeyregValidPeriod`, v31+).
    pub max_keyreg_valid_period: u64,
    /// Keyreg coherency checks enabled (Go: `EnableKeyregCoherencyCheck`, v28+).
    pub enable_keyreg_coherency_check: bool,

    // ── State proofs ────────────────────────────────────────────
    /// Enable state proof keyreg check (Go: `EnableStateProofKeyregCheck`, v31+).
    pub enable_state_proof_keyreg_check: bool,
    /// Frequency of state proofs in rounds (Go: `StateProofInterval`, v34+).
    /// 0 means state proofs are disabled.
    pub state_proof_interval: u64,
    /// How many rounds back the state-proof voters are drawn from
    /// (Go: `StateProofVotersLookback`, v34+).
    pub state_proof_voters_lookback: u64,
    /// Whether the light block header includes the block hash instead of the seed
    /// (Go: `StateProofBlockHashInLightHeader`, v39+).
    pub state_proof_block_hash_in_light_header: bool,
    /// Fraction (numerator over `1<<32`) of top-voters weight that must sign
    /// for a proof to be considered acceptable (Go: `StateProofWeightThreshold`,
    /// v34+).
    pub state_proof_weight_threshold: u32,
    /// Security parameter `k+q` (pre-quantum) or `k+2q` (post-quantum) used by
    /// `crypto/stateproof`'s reveal-count bound (Go: `StateProofStrengthTarget`,
    /// v34+).
    pub state_proof_strength_target: u64,

    // ── Clear state isolation ───────────────────────────────────
    /// Greater isolation for clear state programs (Go: `IsolateClearState`, v31+).
    pub isolate_clear_state: bool,

    // ── Asset URL ───────────────────────────────────────────────
    /// Max asset URL bytes (Go: `MaxAssetURLBytes`).
    pub max_asset_url_bytes: usize,
    /// Max asset name bytes (Go: `MaxAssetNameBytes`).
    pub max_asset_name_bytes: usize,
    /// Max asset unit name bytes (Go: `MaxAssetUnitNameBytes`).
    pub max_asset_unit_name_bytes: usize,
    /// Max asset decimals (Go: `MaxAssetDecimals`, v20+; 0 pre-v20).
    pub max_asset_decimals: u32,

    // ── Expired account removal (v31+) ───────────────────────────
    /// Max online accounts a proposer can take offline for expired voting keys
    /// (Go: `MaxProposedExpiredOnlineAccounts`, v31+).
    pub max_proposed_expired_online_accounts: usize,

    // ── Proposer payouts (v40+) ─────────────────────────────────
    /// Proposer payouts enabled (Go: `Payouts.Enabled`).
    pub payouts_enabled: bool,
    /// GoOnlineFee for proposer payouts (Go: `Payouts.GoOnlineFee`).
    pub payouts_go_online_fee: u64,
    /// Percent of fees to proposer (Go: `Payouts.Percent`).
    pub payouts_percent: u64,
    /// Minimum balance for proposer payouts (Go: `Payouts.MinBalance`).
    pub payouts_min_balance: u64,
    /// Maximum balance for proposer payouts (Go: `Payouts.MaxBalance`).
    pub payouts_max_balance: u64,
    /// Max online accounts a proposer can suspend for not proposing lately
    /// (Go: `Payouts.MaxMarkAbsent`, v40+).
    pub payouts_max_mark_absent: usize,
    /// Challenges occur once every this many rounds (Go: `Payouts.ChallengeInterval`, v40+).
    pub payouts_challenge_interval: u64,
    /// Grace period (in rounds) after a challenge before suspension
    /// (Go: `Payouts.ChallengeGracePeriod`, v40+).
    pub payouts_challenge_grace_period: u64,
    /// Number of leading address bits that must match for a challenge
    /// (Go: `Payouts.ChallengeBits`, v40+).
    pub payouts_challenge_bits: u32,

    // ── Proposer bonus plan (v40+) ──────────────────────────────
    // Go: `config.BonusPlan` (`config/consensus.go`), consulted by
    // `bookkeeping.NextBonus` / `computeBonus` (`data/bookkeeping/block.go`).
    /// Earliest round this bonus plan can apply (Go: `Bonus.BaseRound`).
    pub bonus_base_round: u64,
    /// Bonus paid when this plan first applies; 0 means "don't change the
    /// amount, only the decay rate" (Go: `Bonus.BaseAmount`).
    pub bonus_base_amount: u64,
    /// Rounds between successive 1% decays of the bonus; 0 disables decay
    /// (Go: `Bonus.DecayInterval`).
    pub bonus_decay_interval: u64,

    // ── Misc ────────────────────────────────────────────────────
    /// Support non-participating transactions (Go: `SupportBecomeNonParticipatingTransactions`, v18+).
    pub support_become_non_participating_transactions: bool,
    /// App versioning enabled (Go: `EnableAppVersioning`, v41+).
    pub enable_app_versioning: bool,

    // ── Agreement / committee ──────────────────────────────────
    /// Number of block proposers (Go: `NumProposers`).
    pub num_proposers: u64,
    /// Soft vote committee size (Go: `SoftCommitteeSize`).
    pub soft_committee_size: u64,
    /// Soft vote committee threshold (Go: `SoftCommitteeThreshold`).
    pub soft_committee_threshold: u64,
    /// Cert vote committee size (Go: `CertCommitteeSize`).
    pub cert_committee_size: u64,
    /// Cert vote committee threshold (Go: `CertCommitteeThreshold`).
    pub cert_committee_threshold: u64,
    /// Next step committee size (Go: `NextCommitteeSize`).
    pub next_committee_size: u64,
    /// Next step committee threshold (Go: `NextCommitteeThreshold`).
    pub next_committee_threshold: u64,
    /// Late step committee size (Go: `LateCommitteeSize`).
    pub late_committee_size: u64,
    /// Late step committee threshold (Go: `LateCommitteeThreshold`).
    pub late_committee_threshold: u64,
    /// Redo step committee size (Go: `RedoCommitteeSize`).
    pub redo_committee_size: u64,
    /// Redo step committee threshold (Go: `RedoCommitteeThreshold`).
    pub redo_committee_threshold: u64,
    /// Down step committee size (Go: `DownCommitteeSize`).
    pub down_committee_size: u64,
    /// Down step committee threshold (Go: `DownCommitteeThreshold`).
    pub down_committee_threshold: u64,

    // ── Agreement timeouts ─────────────────────────────────────
    /// Filter timeout for period > 0 (Go: `AgreementFilterTimeout`).
    /// Value should be 2 * SmallLambda.
    pub agreement_filter_timeout: Duration,
    /// Filter timeout for period 0 (Go: `AgreementFilterTimeoutPeriod0`).
    pub agreement_filter_timeout_period0: Duration,
    /// Deadline timeout for period 0 (Go: `AgreementDeadlineTimeoutPeriod0`).
    /// Defaults to BigLambda + SmallLambda.
    pub agreement_deadline_timeout_period0: Duration,
    /// Time between fast recovery attempts (Go: `FastRecoveryLambda`).
    pub fast_recovery_lambda: Duration,

    // ── Seed / sortition ───────────────────────────────────────
    /// How many blocks back we use seeds from in sortition, delta_s in the spec (Go: `SeedLookback`).
    pub seed_lookback: u64,
    /// How often an old block hash is mixed into the seed, delta_r in the spec (Go: `SeedRefreshInterval`).
    pub seed_refresh_interval: u64,
    /// Max balance lookback for sortition (Go: `MaxBalLookback`).
    pub max_bal_lookback: u64,

    // ── Key management ─────────────────────────────────────────
    /// Granularity of top-level ephemeral keys (Go: `DefaultKeyDilution`).
    pub default_key_dilution: u64,
    /// Domain-separated credentials (Go: `CredentialDomainSeparationEnabled`, v16+).
    pub credential_domain_separation_enabled: bool,

    // ── Dynamic filter ─────────────────────────────────────────
    /// Whether filter timeout is set dynamically based on credential arrival times
    /// (Go: `DynamicFilterTimeout`, v39+).
    pub dynamic_filter_timeout: bool,

    // ── Online circulation ──────────────────────────────────────
    /// Excludes stake behind expired participation keys from the total
    /// online stake used by agreement's `Circulation` and by
    /// `GET /v2/ledger/supply`'s `online-stake` (Go: `ExcludeExpiredCirculation`,
    /// v38+).
    pub exclude_expired_circulation: bool,

    // ── Protocol upgrade vote (Go: `data/bookkeeping/block.go`
    // `applyUpgradeVote`/`ProcessUpgradeParams`) ─────────────────
    /// The upgrade proposal this protocol version's block proposer will make
    /// by default when no upgrade is currently pending: the target protocol
    /// version and the wait-rounds delay between vote acceptance and
    /// switch-over (Go: `ApprovedUpgrades`, a `map[ConsensusVersion]uint64`).
    /// In go-algorand's own version history this map is reset to `{}` at
    /// every version boundary and then populated with at most one
    /// `vN.ApprovedUpgrades[vN+1] = delay` entry (`config/consensus.go`), so
    /// it is modeled here as `Option<(target version, delay)>` rather than a
    /// full map. `None` means this version proposes no upgrade.
    pub approved_upgrade: Option<(&'static str, u64)>,
    /// Rounds an upgrade proposal is voted on before its fate (accepted or
    /// expired) is decided (Go: `UpgradeVoteRounds`).
    pub upgrade_vote_rounds: u64,
    /// Minimum fraction of yes-votes, out of `upgrade_vote_rounds`, needed to
    /// accept a pending upgrade proposal (Go: `UpgradeThreshold`).
    pub upgrade_threshold: u64,
    /// Wait-rounds delay used when a proposal specifies `UpgradeDelay == 0`
    /// (Go: `DefaultUpgradeWaitRounds`).
    pub default_upgrade_wait_rounds: u64,
    /// Minimum permissible `UpgradeDelay` for a new proposal, inclusive
    /// (Go: `MinUpgradeWaitRounds`, v22+; zero before that).
    pub min_upgrade_wait_rounds: u64,
    /// Maximum permissible `UpgradeDelay` for a new proposal, inclusive
    /// (Go: `MaxUpgradeWaitRounds`, v22+; zero before that).
    pub max_upgrade_wait_rounds: u64,

    // ── Rewards fixes (historical-replay correctness) ───────────
    /// Fix the rewards calculation by avoiding subtracting too much from the
    /// rewards pool: the outstanding `RewardsResidue` counts against what the
    /// pool may spend when the rate refreshes (Go: `PendingResidueRewards`,
    /// v18+). Before v18, only `MinBalance` was reserved, not
    /// `MinBalance + RewardsResidue`.
    pub pending_residue_rewards: bool,
    /// Update the *genesis* rewards-rate calculation to take the reward
    /// pool's minimum balance into account (Go: `InitialRewardsRateCalculation`,
    /// v26+): `(poolBalance - MinBalance) / RewardsRateRefreshInterval`
    /// instead of `poolBalance / RewardsRateRefreshInterval`. Baked once into
    /// the genesis block's `RewardsRate`, so it only matters for historical
    /// replay of a chain whose genesis predates v26 (this never changes
    /// after genesis is created).
    pub initial_rewards_rate_calculation: bool,
    /// When the rewards rate refreshes at a recalculation round, use the
    /// freshly-refreshed rate immediately for that same round's level
    /// advance, rather than the previous round's rate (Go:
    /// `RewardsCalculationFix`, v31+).
    pub rewards_calculation_fix: bool,

    // ── Inner transaction IDs (historical-replay correctness) ────
    /// Enables a consistent, unified way of computing inner transaction IDs
    /// that is correctly recursive through multiple levels of nesting (Go:
    /// `UnifyInnerTxIDs`, v34+). Before v34, a nested (2+ levels deep) inner
    /// transaction's ID was derived from its immediate parent's *raw* txn
    /// hash rather than that parent's own correctly-computed (possibly
    /// itself-nested) ID.
    pub unify_inner_tx_ids: bool,

    // ── Account existence (live semantics) ───────────────────────
    /// Ensures that accounts with no balance (so they don't even "exist")
    /// can still be a transaction sender without being forced into
    /// existence by a rewards-bookkeeping write: avoids persisting a
    /// rewards-base update to an account that has zero balance and whose
    /// balance this transaction leaves unchanged (Go: `UnfundedSenders`,
    /// v34+).
    pub unfunded_senders: bool,

    // ── ECDSA precheck (historical-replay correctness) ───────────
    /// The `ecdsa_verify` opcode bails early, returning `false`, if the
    /// supplied Secp256r1 public key is not on the curve, instead of
    /// (pre-fix) proceeding directly to signature verification with a
    /// possibly-invalid point (Go: `EnablePrecheckECDSACurve`, v38+).
    pub enable_precheck_ecdsa_curve: bool,

    // ── Low-resource-ID restrictions (live-acceptance risk) ──────
    /// Forbids AVM opcodes from resolving asset/application IDs <= 255 (to
    /// reduce ambiguity with slot-index references), and raises the first
    /// asset/app ID allocated on a new chain's genesis to 1001 (Go:
    /// `AppForbidLowResources`, v38+).
    pub app_forbid_low_resources: bool,

    // ── State proofs (live-acceptance risk) ──────────────────────
    /// Bound on how many online accounts (top-N by normalized balance)
    /// participate in forming a state proof's voter-commitment vector (Go:
    /// `StateProofTopVoters`, v34+ = 1024). Zero means state proofs are not
    /// yet consensus-active for this version (matches `state_proof_interval
    /// == 0`).
    pub state_proof_top_voters: u64,

    // ── LogicSig authorization modes (issue #752) ──────────────────
    /// Legacy ed25519-multisig LogicSig delegation is accepted (Go:
    /// `LogicSigMsig`, v18+, retired at v41 in favor of `LogicSigLMsig`).
    pub logic_sig_msig: bool,
    /// Newer lhash-based multisig LogicSig delegation ("LMsig") is accepted
    /// (Go: `LogicSigLMsig`, v41+, replaces `LogicSigMsig` in the same
    /// release).
    pub logic_sig_lmsig: bool,

    // ── I/O budget error classification (issue #752) ───────────────
    /// Box read-I/O-budget overruns are a bare error rather than a
    /// `logic.EvalError` (Go: `EnableBareBudgetError`, v38+). This matters
    /// only for ClearState-program semantics: go's
    /// `ledger/apply/application.go` swallows a ClearState program's
    /// `logic.EvalError` unconditionally (clearing out is always allowed)
    /// but re-propagates any *other* error kind, failing the outer
    /// transaction. Before v38, an io-budget overrun was itself an
    /// `EvalError` and so was swallowed like any other ClearState failure;
    /// from v38 on it is a bare error and fails the transaction.
    /// Approval-program semantics are unaffected either way (any error there
    /// already fails the transaction, regardless of error kind).
    pub enable_bare_budget_error: bool,

    // ── State proof catch-up / verification source (issue #752) ────
    /// Number of state-proof intervals the node will try to catch up with
    /// before giving up and releasing resources reserved for building state
    /// proofs (Go: `StateProofMaxRecoveryIntervals`, v34+ = 10). A
    /// resource-management/liveness knob, not a block-acceptance rule; 0
    /// before v34 (state proofs not yet consensus-active).
    pub state_proof_max_recovery_intervals: u64,
    /// Whether the node sources state-proof verification data from the
    /// state-proof verification tracker rather than recomputing it (Go:
    /// `StateProofUseTrackerVerification`, v38+). An internal
    /// implementation-detail toggle for *where* verification data comes
    /// from, with no live-consensus-acceptance impact.
    pub state_proof_use_tracker_verification: bool,

    // ── Catchpoint / on-disk format (issue #752) ────────────────────
    /// Round lookback used to decide which round's account snapshot becomes
    /// the next catchpoint: the snapshot for round X is taken at
    /// `X - CatchpointLookback` (Go: `CatchpointLookback`, v33+ = 320).
    /// Distinct from [`Self::max_bal_lookback`] (Go: `MaxBalLookback`), which
    /// bounds online-account history retention and only happens to share the
    /// same numeric value (320) at every version modeled here.
    pub catchpoint_lookback: u64,
    /// Enables `UpdateRound` on-disk in account/resource records and
    /// catchpoint merkle-trie keys (Go: `EnableLedgerDataUpdateRound`,
    /// v32+). Per go's own doc comment this is never reflected in on-chain
    /// state and has zero live-consensus-acceptance impact —
    /// catchpoint-file-format only.
    pub enable_ledger_data_update_round: bool,
    /// Enables version-7 catchpoint files (adds state-proof verification
    /// contexts and catchpoint-label versioning) (Go:
    /// `EnableCatchpointsWithSPContexts`, v38+).
    pub enable_catchpoints_with_sp_contexts: bool,
    /// Enables version-8 catchpoint files (adds `onlineaccounts` /
    /// `onlineroundparamstail` tables, for historical stake lookups) (Go:
    /// `EnableCatchpointsWithOnlineAccounts`, v40+). go-algorand requires
    /// [`Self::enable_catchpoints_with_sp_contexts`] to also be true whenever
    /// this is true (v8 catchpoints carry v7's SP contexts too).
    pub enable_catchpoints_with_online_accounts: bool,
}

impl ConsensusParams {
    /// Mirrors go's `ConsensusParams.TxnSizePricingEnabled()` (`config/consensus.go`):
    /// transaction-size pricing (v42+) is enabled exactly when a non-zero
    /// per-byte surcharge is configured. This gates whether a heartbeat's
    /// challenge fee discount is claimed via the explicit
    /// `HeartbeatTxnFields::hb_challenge_discount` flag (when enabled) or
    /// inferred from an underpaying singleton heartbeat (when not).
    pub fn txn_size_pricing_enabled(&self) -> bool {
        self.per_byte_txn_surcharge != 0
    }

    /// Mirrors go's `ConsensusParams.PQSchemeEnabled(scheme)` (`config/consensus.go`,
    /// v42+): whether the given post-quantum signature scheme is enabled under
    /// these consensus parameters. Only Falcon-1024 (`"f1"`) is currently
    /// recognized; any other scheme tag (including the reserved-but-unwired
    /// Falcon-512 `"f2"`) is not enabled.
    pub fn pq_scheme_enabled(&self, scheme: [u8; 2]) -> bool {
        match &scheme {
            b"f1" => self.enable_pq_scheme_falcon1024,
            _ => false,
        }
    }

    /// Mirrors go's `ConsensusParams.PQSigEnabled()` (`config/consensus.go`,
    /// v42+): whether *any* post-quantum signature scheme is enabled. Used by
    /// the pre-activation gate (`data/transactions/verify/txn.go`'s
    /// `stxnCoreChecks`) to hard-reject a non-blank `PQsig` before any scheme
    /// is even known to be supported.
    pub fn pq_sig_enabled(&self) -> bool {
        self.enable_pq_scheme_falcon1024
    }

    /// Mirrors go's `ConsensusParams.PQSchemeFeeContribution(scheme)`
    /// (`config/consensus.go`, v42+): the additional fee-factor surcharge (in
    /// fixed-point `Micros`, `1_000_000` == one `MinTxnFee`) charged for a
    /// transaction authorized with the given PQ scheme. Falcon-1024 costs 2x
    /// the base min fee; any other/unknown scheme (including the
    /// reserved-but-unwired Falcon-512) contributes zero, matching upstream's
    /// "an unknown PQ scheme contributes zero, which is safe because the
    /// transaction will be rejected during verification" comment.
    pub fn pq_scheme_fee_contribution(&self, scheme: [u8; 2]) -> u64 {
        match &scheme {
            b"f1" => 2_000_000,
            _ => 0,
        }
    }
}

/// Payset commit types matching go-algorand.
pub const PAYSET_COMMIT_UNSUPPORTED: u8 = 0;
pub const PAYSET_COMMIT_FLAT: u8 = 1;
pub const PAYSET_COMMIT_MERKLE: u8 = 2;

impl Default for ConsensusParams {
    /// Default returns V42 (current consensus) parameters.
    fn default() -> Self {
        consensus_params_for_version(CONSENSUS_V42).expect("V42 must be a known protocol version")
    }
}

/// Return consensus parameters for the given protocol version string.
///
/// All values match go-algorand `config/consensus.go` at tag v4.6.0-stable.
/// Each version inherits from its predecessor and overrides specific fields,
/// exactly mirroring go-algorand's `initConsensusProtocols()`.
///
/// Returns `None` for unknown protocol versions.
///
/// # Consensus.json overrides (issue #762)
///
/// Before anything else, this consults the process-global override registry
/// populated (at most once, at startup) by [`install_consensus_overrides`].
/// A version present in that registry wins wholesale -- `Some(params)` for a
/// version a loaded `consensus.json` replaced or added, `None` for one it
/// deleted -- exactly mirroring go-algorand's single mutable package-level
/// `config.Consensus` map, which every caller of `config.Consensus[version]`
/// transparently observes once `LoadConfigurableConsensusProtocols` has run.
///
/// When the registry has never been installed (the default for the
/// overwhelming majority of this workspace's tests, tools, and any code path
/// that never goes through `bin/algod-rust`'s real startup), or for any
/// version the loaded overrides never touched, this falls through to the
/// exact same compile-time computation below as before this feature
/// existed -- zero behavior change.
pub fn consensus_params_for_version(version: &str) -> Option<ConsensusParams> {
    if let Some(overrides) = CONSENSUS_OVERRIDES.get() {
        if let Some(entry) = overrides.get(version) {
            return entry.clone();
        }
    }

    // Build the v7 base and walk forward to find the right version.
    // This mirrors go-algorand's initConsensusProtocols exactly.

    // ── v7 base ─────────────────────────────────────────────────
    let v7 = ConsensusParams {
        logic_sig_version: 0,
        logic_sig_max_size: 0,
        max_absolute_logic_sig_program_size: 0,
        logic_sig_max_cost: 0,
        max_app_program_cost: 0,
        min_balance: 10_000,
        min_txn_fee: 1_000,
        max_txn_life: 1_000,
        max_txn_note_bytes: 1_024,
        max_tx_group_size: 1,
        max_txn_bytes_per_block: 1_000_000,
        max_absolute_txn_note_bytes: 0,
        max_absolute_extra_program_pages: 0,
        max_absolute_total_arg_len: 0,
        per_byte_txn_surcharge: 0,
        enable_fee_pooling: false,
        support_tx_groups: false,
        support_transaction_leases: false,
        fix_transaction_leases: false,
        support_rekeying: false,
        enable_heartbeat: false,
        enforce_auth_addr_sender_diff: false,
        load_tracking: false,
        app_size_updates: false,
        allow_zero_local_app_ref: false,
        enable_pq_scheme_falcon1024: false,
        enable_select_f128: false,
        enable_logicsig_size_pooling: false,
        enable_logicsig_cost_pooling: false,
        enable_app_cost_pooling: false,
        enable_inner_transaction_pooling: false,
        application: false,
        asset: false,
        max_inner_transactions: 0,
        min_inner_appl_version: 0,
        max_app_key_len: 0,
        max_app_bytes_value_len: 0,
        max_app_sum_key_value_lens: 0,
        max_extra_app_program_pages: 0,
        max_app_program_len: 0,
        max_app_total_program_len: 0,
        max_global_schema_entries: 0,
        max_local_schema_entries: 0,
        max_app_args: 0,
        max_app_total_arg_len: 0,
        max_app_txn_accounts: 0,
        max_app_txn_foreign_apps: 0,
        max_app_txn_foreign_assets: 0,
        max_app_total_txn_references: 0,
        max_app_access: 0,
        max_box_size: 0,
        bytes_per_box_reference: 0,
        max_app_box_references: 0,
        enable_box_ref_name_error: false,
        app_flat_params_min_balance: 0,
        app_flat_opt_in_min_balance: 0,
        schema_min_balance_per_entry: 0,
        schema_uint_min_balance: 0,
        schema_bytes_min_balance: 0,
        box_flat_min_balance: 0,
        box_byte_min_balance: 0,
        maximum_minimum_balance: 0,
        max_assets_per_account: 0,
        max_log_size: 1024,
        max_log_calls: 32,
        deeper_block_header_history: 0,
        reward_unit: 1_000_000,
        rewards_rate_refresh_interval: 500_000,
        max_timestamp_increment: 25,
        payset_commit: PAYSET_COMMIT_UNSUPPORTED,
        enable_sha256_txn_commitment_header: false,
        enable_sha512_block_hash: false,
        require_genesis_hash: false,
        support_genesis_hash: false,
        max_apps_created: 0,
        max_apps_opted_in: 0,
        max_keyreg_valid_period: 0,
        enable_keyreg_coherency_check: false,
        enable_state_proof_keyreg_check: false,
        state_proof_interval: 0,
        state_proof_voters_lookback: 0,
        state_proof_block_hash_in_light_header: false,
        state_proof_weight_threshold: 0,
        state_proof_strength_target: 0,
        isolate_clear_state: false,
        max_asset_url_bytes: 0,
        max_asset_name_bytes: 0,
        max_asset_unit_name_bytes: 0,
        max_asset_decimals: 0,
        max_proposed_expired_online_accounts: 0,
        payouts_enabled: false,
        payouts_go_online_fee: 0,
        payouts_percent: 0,
        payouts_min_balance: 0,
        payouts_max_balance: 0,
        payouts_max_mark_absent: 0,
        payouts_challenge_interval: 0,
        payouts_challenge_grace_period: 0,
        payouts_challenge_bits: 0,
        bonus_base_round: 0,
        bonus_base_amount: 0,
        bonus_decay_interval: 0,
        support_become_non_participating_transactions: false,
        enable_app_versioning: false,
        // Agreement / committee
        num_proposers: 30,
        soft_committee_size: 2500,
        soft_committee_threshold: 1870,
        cert_committee_size: 1000,
        cert_committee_threshold: 720,
        next_committee_size: 10000,
        next_committee_threshold: 7750,
        late_committee_size: 10000,
        late_committee_threshold: 7750,
        redo_committee_size: 10000,
        redo_committee_threshold: 7750,
        down_committee_size: 10000,
        down_committee_threshold: 7750,
        // Agreement timeouts
        agreement_filter_timeout: Duration::from_secs(4),
        agreement_filter_timeout_period0: Duration::from_secs(4),
        // BigLambda (15s) + SmallLambda (2s) = 17s
        agreement_deadline_timeout_period0: Duration::from_millis(17000),
        fast_recovery_lambda: Duration::from_secs(300), // 5 minutes
        // Seed / sortition
        seed_lookback: 2,
        seed_refresh_interval: 100,
        max_bal_lookback: 320,
        // Key management
        default_key_dilution: 10000,
        credential_domain_separation_enabled: false,
        // Dynamic filter
        dynamic_filter_timeout: false,
        exclude_expired_circulation: false,
        // Protocol upgrade vote (Go base struct: config/consensus.go's
        // `initConsensusProtocols`, the values set on the v7-equivalent
        // struct literal before any version-specific overrides).
        approved_upgrade: None,
        upgrade_vote_rounds: 10_000,
        upgrade_threshold: 9_000,
        default_upgrade_wait_rounds: 10_000,
        min_upgrade_wait_rounds: 0,
        max_upgrade_wait_rounds: 0,
        pending_residue_rewards: false,
        initial_rewards_rate_calculation: false,
        rewards_calculation_fix: false,
        unify_inner_tx_ids: false,
        unfunded_senders: false,
        enable_precheck_ecdsa_curve: false,
        app_forbid_low_resources: false,
        state_proof_top_voters: 0,
        logic_sig_msig: false,
        logic_sig_lmsig: false,
        enable_bare_budget_error: false,
        state_proof_max_recovery_intervals: 0,
        state_proof_use_tracker_verification: false,
        catchpoint_lookback: 0,
        enable_ledger_data_update_round: false,
        enable_catchpoints_with_sp_contexts: false,
        enable_catchpoints_with_online_accounts: false,
    };
    if version == CONSENSUS_V7 {
        return Some(v7);
    }

    // ── v8 ──────────────────────────────────────────────────────
    let mut v8 = v7.clone();
    // v8 uses parameters and a seed derivation policy from Georgios' new analysis
    v8.seed_refresh_interval = 80;
    v8.num_proposers = 9;
    v8.soft_committee_size = 2990;
    v8.soft_committee_threshold = 2267;
    v8.cert_committee_size = 1500;
    v8.cert_committee_threshold = 1112;
    v8.next_committee_size = 5000;
    v8.next_committee_threshold = 3838;
    v8.late_committee_size = 5000;
    v8.late_committee_threshold = 3838;
    v8.redo_committee_size = 5000;
    v8.redo_committee_threshold = 3838;
    v8.down_committee_size = 5000;
    v8.down_committee_threshold = 3838;
    if version == CONSENSUS_V8 {
        return Some(v8);
    }

    // ── v9 ──────────────────────────────────────────────────────
    let mut v9 = v8.clone();
    v9.min_balance = 100_000;
    if version == CONSENSUS_V9 {
        return Some(v9);
    }

    // ── v10 ─────────────────────────────────────────────────────
    let mut v10 = v9.clone();
    // v10 introduces fast partition recovery (and also raises NumProposers)
    v10.num_proposers = 20;
    v10.late_committee_size = 500;
    v10.late_committee_threshold = 320;
    v10.redo_committee_size = 2400;
    v10.redo_committee_threshold = 1768;
    v10.down_committee_size = 6000;
    v10.down_committee_threshold = 4560;
    if version == CONSENSUS_V10 {
        return Some(v10);
    }

    // ── v11 ─────────────────────────────────────────────────────
    let mut v11 = v10.clone();
    v11.payset_commit = PAYSET_COMMIT_FLAT;
    if version == CONSENSUS_V11 {
        return Some(v11);
    }

    // ── v12 ─────────────────────────────────────────────────────
    let v12 = v11.clone();
    // v12 only increases MaxVersionStringLen (not modeled)
    if version == CONSENSUS_V12 {
        return Some(v12);
    }

    // ── v13 ─────────────────────────────────────────────────────
    let v13 = v12.clone();
    if version == CONSENSUS_V13 {
        return Some(v13);
    }

    // ── v14 ─────────────────────────────────────────────────────
    let mut v14 = v13.clone();
    v14.support_genesis_hash = true;
    if version == CONSENSUS_V14 {
        return Some(v14);
    }

    // ── v15 ─────────────────────────────────────────────────────
    let v15 = v14.clone();
    // v15 adds RewardsInApplyData, ForceNonParticipatingFeeSink (not modeled)
    if version == CONSENSUS_V15 {
        return Some(v15);
    }

    // ── v16 ─────────────────────────────────────────────────────
    let mut v16 = v15.clone();
    v16.credential_domain_separation_enabled = true;
    v16.require_genesis_hash = true;
    if version == CONSENSUS_V16 {
        return Some(v16);
    }

    // ── v17 ─────────────────────────────────────────────────────
    let v17 = v16.clone();
    if version == CONSENSUS_V17 {
        return Some(v17);
    }

    // ── v18 ─────────────────────────────────────────────────────
    let mut v18 = v17.clone();
    v18.asset = true;
    v18.logic_sig_version = 1;
    v18.logic_sig_max_size = 1000;
    v18.max_absolute_logic_sig_program_size = 1000;
    v18.logic_sig_max_cost = 20_000;
    v18.max_assets_per_account = 1000;
    v18.support_tx_groups = true;
    v18.max_tx_group_size = 16;
    v18.support_transaction_leases = true;
    v18.support_become_non_participating_transactions = true;
    v18.max_asset_name_bytes = 32;
    v18.max_asset_unit_name_bytes = 8;
    v18.max_asset_url_bytes = 32;
    // Go: v18.PendingResidueRewards = true (config/consensus.go:1058).
    v18.pending_residue_rewards = true;
    // Go: v18.LogicSigMsig = true (config/consensus.go:1066), formalizing
    // msig-authorized LogicSigs that were unconditionally allowed since v18
    // (retroactively added to the v18 struct literal by commit `3b1ac0f59`
    // alongside `LogicSigLMsig`; see issue #752).
    v18.logic_sig_msig = true;
    if version == CONSENSUS_V18 {
        return Some(v18);
    }

    // ── v19 ─────────────────────────────────────────────────────
    let v19 = v18.clone();
    if version == CONSENSUS_V19 {
        return Some(v19);
    }

    // ── v20 ─────────────────────────────────────────────────────
    let mut v20 = v19.clone();
    // v20 adds MaxAssetDecimals and changes DefaultUpgradeWaitRounds
    v20.default_upgrade_wait_rounds = 140_000;
    v20.max_asset_decimals = 19;
    if version == CONSENSUS_V20 {
        return Some(v20);
    }

    // ── v21 ─────────────────────────────────────────────────────
    let v21 = v20.clone();
    if version == CONSENSUS_V21 {
        return Some(v21);
    }

    // ── v22 ─────────────────────────────────────────────────────
    let mut v22 = v21.clone();
    // v22 adds MinUpgradeWaitRounds, MaxUpgradeWaitRounds
    v22.min_upgrade_wait_rounds = 10_000;
    v22.max_upgrade_wait_rounds = 150_000;
    if version == CONSENSUS_V22 {
        return Some(v22);
    }

    // ── v23 ─────────────────────────────────────────────────────
    let mut v23 = v22.clone();
    v23.fix_transaction_leases = true;
    if version == CONSENSUS_V23 {
        return Some(v23);
    }

    // ── v24 ─────────────────────────────────────────────────────
    let mut v24 = v23.clone();
    v24.logic_sig_version = 2;
    v24.application = true;
    v24.min_inner_appl_version = 6;
    v24.support_rekeying = true;
    // 100.1 Algos (MinBalance for creating 1,000 assets)
    v24.maximum_minimum_balance = 100_100_000;
    v24.max_app_args = 16;
    v24.max_app_total_arg_len = 2048;
    v24.max_app_program_len = 1024;
    v24.max_app_total_program_len = 2048;
    v24.max_app_key_len = 64;
    v24.max_app_bytes_value_len = 64;
    v24.max_app_sum_key_value_lens = 128;
    v24.app_flat_params_min_balance = 100_000;
    v24.app_flat_opt_in_min_balance = 100_000;
    v24.max_app_txn_accounts = 4;
    v24.max_app_txn_foreign_apps = 2;
    v24.max_app_txn_foreign_assets = 2;
    v24.max_app_total_txn_references = 8;
    v24.schema_min_balance_per_entry = 25_000;
    v24.schema_uint_min_balance = 3_500;
    v24.schema_bytes_min_balance = 25_000;
    v24.max_local_schema_entries = 16;
    v24.max_global_schema_entries = 64;
    v24.max_app_program_cost = 700;
    v24.max_apps_created = 10;
    v24.max_apps_opted_in = 10;
    if version == CONSENSUS_V24 {
        return Some(v24);
    }

    // ── v25 ─────────────────────────────────────────────────────
    let v25 = v24.clone();
    // v25 enables EnableAssetCloseAmount (not modeled)
    if version == CONSENSUS_V25 {
        return Some(v25);
    }

    // ── v26 ─────────────────────────────────────────────────────
    let mut v26 = v25.clone();
    v26.logic_sig_version = 3;
    v26.payset_commit = PAYSET_COMMIT_MERKLE;
    // Go: v26.InitialRewardsRateCalculation = true (config/consensus.go:1213).
    v26.initial_rewards_rate_calculation = true;
    if version == CONSENSUS_V26 {
        return Some(v26);
    }

    // ── v27 ─────────────────────────────────────────────────────
    let v27 = v26.clone();
    // v27 enables NoEmptyLocalDeltas (not modeled)
    if version == CONSENSUS_V27 {
        return Some(v27);
    }

    // ── v28 ─────────────────────────────────────────────────────
    let mut v28 = v27.clone();
    v28.logic_sig_version = 4;
    v28.max_extra_app_program_pages = 3;
    v28.max_absolute_extra_program_pages = 3;
    v28.max_app_program_len = 2048;
    v28.max_asset_url_bytes = 96;
    v28.max_app_bytes_value_len = 128;
    v28.max_app_txn_foreign_apps = 8;
    v28.max_app_txn_foreign_assets = 8;
    v28.enable_fee_pooling = true;
    v28.enable_keyreg_coherency_check = true;
    if version == CONSENSUS_V28 {
        return Some(v28);
    }

    // ── v29 ─────────────────────────────────────────────────────
    let v29 = v28.clone();
    // v29 enables EnableProperExtraPageAccounting (not modeled)
    if version == CONSENSUS_V29 {
        return Some(v29);
    }

    // ── v30 ─────────────────────────────────────────────────────
    let mut v30 = v29.clone();
    v30.logic_sig_version = 5;
    v30.enable_app_cost_pooling = true;
    v30.max_inner_transactions = 16;
    v30.max_apps_opted_in = 50;
    if version == CONSENSUS_V30 {
        return Some(v30);
    }

    // ── v31 ─────────────────────────────────────────────────────
    let mut v31 = v30.clone();
    v31.logic_sig_version = 6;
    v31.enable_inner_transaction_pooling = true;
    v31.isolate_clear_state = true;
    v31.enable_state_proof_keyreg_check = true;
    v31.max_keyreg_valid_period = 256 * (1 << 16) - 1;
    v31.max_proposed_expired_online_accounts = 32;
    // Go: v31.RewardsCalculationFix = true (config/consensus.go:1312).
    v31.rewards_calculation_fix = true;
    if version == CONSENSUS_V31 {
        return Some(v31);
    }

    // ── v32 ─────────────────────────────────────────────────────
    let mut v32 = v31.clone();
    v32.max_assets_per_account = 0; // unlimited
    v32.max_apps_created = 0; // unlimited
    v32.max_apps_opted_in = 0; // unlimited
    v32.maximum_minimum_balance = 0; // remove limit
                                     // Go: v32.EnableLedgerDataUpdateRound = true (config/consensus.go:1338).
                                     // Catchpoint-file-format-only: never appears in on-chain state (issue #752).
    v32.enable_ledger_data_update_round = true;
    if version == CONSENSUS_V32 {
        return Some(v32);
    }

    // ── v33 ─────────────────────────────────────────────────────
    let mut v33 = v32.clone();
    v33.deeper_block_header_history = 1;
    v33.max_txn_bytes_per_block = 5 * 1024 * 1024;
    // Go: v33.CatchpointLookback = 320 (config/consensus.go:1362). Distinct
    // from `max_bal_lookback`, which already carries 320 unconditionally
    // from the v7 base (issue #752).
    v33.catchpoint_lookback = 320;
    if version == CONSENSUS_V33 {
        return Some(v33);
    }

    // ── v34 ─────────────────────────────────────────────────────
    let mut v34 = v33.clone();
    v34.logic_sig_version = 7;
    v34.min_inner_appl_version = 4;
    v34.enable_sha256_txn_commitment_header = true;
    // Go: v34.StateProofMaxRecoveryIntervals = 10 (config/consensus.go:1383).
    v34.state_proof_max_recovery_intervals = 10;
    v34.state_proof_interval = 256;
    v34.state_proof_voters_lookback = 16;
    // Go: v34.StateProofWeightThreshold = (1 << 32) * 30 / 100 (config/consensus.go:1307).
    v34.state_proof_weight_threshold = (((1u64 << 32) * 30) / 100) as u32;
    // Go: v34.StateProofStrengthTarget = 256 (config/consensus.go:1308).
    v34.state_proof_strength_target = 256;
    v34.agreement_filter_timeout_period0 = Duration::from_millis(3400);
    // Go: v34.StateProofTopVoters = 1024, v34.UnifyInnerTxIDs = true,
    // v34.UnfundedSenders = true (config/consensus.go:1379,1388,1392).
    v34.state_proof_top_voters = 1024;
    v34.unify_inner_tx_ids = true;
    v34.unfunded_senders = true;
    if version == CONSENSUS_V34 {
        return Some(v34);
    }

    // ── v35 ─────────────────────────────────────────────────────
    let v35 = v34.clone();
    // v35 enables StateProofExcludeTotalWeightWithRewards (not modeled)
    if version == CONSENSUS_V35 {
        return Some(v35);
    }

    // ── v36 ─────────────────────────────────────────────────────
    let mut v36 = v35.clone();
    v36.logic_sig_version = 8;
    v36.max_box_size = 32_768;
    v36.box_flat_min_balance = 2_500;
    v36.box_byte_min_balance = 400;
    v36.max_app_box_references = 8;
    v36.bytes_per_box_reference = 1_024;
    if version == CONSENSUS_V36 {
        return Some(v36);
    }

    // ── v37 ─────────────────────────────────────────────────────
    let v37 = v36.clone();
    if version == CONSENSUS_V37 {
        return Some(v37);
    }

    // ── v38 ─────────────────────────────────────────────────────
    let mut v38 = v37.clone();
    v38.logic_sig_version = 9;
    v38.agreement_filter_timeout_period0 = Duration::from_millis(3000);
    // online circulation on-demand expiration (config/consensus.go v38)
    v38.exclude_expired_circulation = true;
    v38.enable_box_ref_name_error = true;
    // Go: v38.EnablePrecheckECDSACurve = true, v38.AppForbidLowResources = true
    // (config/consensus.go:1446-1447).
    v38.enable_precheck_ecdsa_curve = true;
    v38.app_forbid_low_resources = true;
    // Go: v38.StateProofUseTrackerVerification = true,
    // v38.EnableCatchpointsWithSPContexts = true (config/consensus.go:1438-1439),
    // v38.EnableBareBudgetError = true (config/consensus.go:1448) (issue #752).
    v38.state_proof_use_tracker_verification = true;
    v38.enable_catchpoints_with_sp_contexts = true;
    v38.enable_bare_budget_error = true;
    if version == CONSENSUS_V38 {
        return Some(v38);
    }

    // ── v39 ─────────────────────────────────────────────────────
    let mut v39 = v38.clone();
    v39.logic_sig_version = 10;
    v39.enable_logicsig_cost_pooling = true;
    v39.state_proof_block_hash_in_light_header = true;
    v39.agreement_deadline_timeout_period0 = Duration::from_secs(4);
    v39.dynamic_filter_timeout = true;
    v39.max_upgrade_wait_rounds = 250_000;
    if version == CONSENSUS_V39 {
        return Some(v39);
    }

    // ── v40 ─────────────────────────────────────────────────────
    let mut v40 = v39.clone();
    v40.logic_sig_version = 11;
    v40.enable_logicsig_size_pooling = true;
    v40.max_absolute_logic_sig_program_size = 16_000;
    v40.enable_heartbeat = true;
    v40.payouts_enabled = true;
    v40.payouts_percent = 50;
    v40.payouts_go_online_fee = 2_000_000;
    v40.payouts_min_balance = 30_000_000_000;
    v40.payouts_max_balance = 70_000_000_000_000;
    v40.payouts_max_mark_absent = 32;
    v40.payouts_challenge_interval = 1_000;
    v40.payouts_challenge_grace_period = 200;
    v40.payouts_challenge_bits = 5;
    // go: config/consensus.go — `v40.Bonus.BaseAmount = 10_000_000` (10 Algos)
    // and `v40.Bonus.DecayInterval = 1_000_000` (~1% decay per 1M rounds).
    // `BaseRound` is left at its zero value, so the plan applies at upgrade time.
    v40.bonus_base_amount = 10_000_000;
    v40.bonus_decay_interval = 1_000_000;
    // Go: v40.EnableCatchpointsWithOnlineAccounts = true (config/consensus.go:1504).
    v40.enable_catchpoints_with_online_accounts = true;
    if version == CONSENSUS_V40 {
        return Some(v40);
    }

    // ── v41 ─────────────────────────────────────────────────────
    let mut v41 = v40.clone();
    v41.logic_sig_version = 12;
    v41.enable_app_versioning = true;
    v41.enable_sha512_block_hash = true;
    v41.max_app_txn_accounts = 8;
    v41.max_app_access = 16;
    v41.bytes_per_box_reference = 2_048;
    // Go: v41.LogicSigMsig = false, v41.LogicSigLMsig = true
    // (config/consensus.go:1525-1526) -- v41 retires ed25519-multisig
    // LogicSig delegation in favor of the newer lhash-based `LMsig` mode
    // (issue #752).
    v41.logic_sig_msig = false;
    v41.logic_sig_lmsig = true;
    // v41 can be upgraded to v42, with a wait delay of 7d
    // (208000 = 7 * 24 * 60 * 60 / ~2.9s ballpark round time), per
    // `config/consensus.go`: `v41.ApprovedUpgrades[protocol.ConsensusV42] = 208000`.
    v41.approved_upgrade = Some((CONSENSUS_V42, 208_000));
    if version == CONSENSUS_V41 {
        return Some(v41);
    }

    // ── v42 ─────────────────────────────────────────────────────
    // go: config/consensus.go, commit 88fe542f3 ("Consensus: Upgrade to
    // consensus version v42 (#6677)"). v42 := v41 with ApprovedUpgrades
    // reset and the fields below overridden.
    let mut v42 = v41.clone();
    // v42 resets ApprovedUpgrades to an empty map (no known approved upgrade
    // beyond v42 yet) — go: `v42.ApprovedUpgrades = map[...]{}`.
    v42.approved_upgrade = None;
    v42.logic_sig_version = 13;
    v42.app_size_updates = true;
    v42.allow_zero_local_app_ref = true;
    v42.enforce_auth_addr_sender_diff = true;
    v42.enable_pq_scheme_falcon1024 = true;
    v42.load_tracking = true;
    v42.max_absolute_txn_note_bytes = 4_096; // same as largest AVM value
    v42.max_absolute_extra_program_pages = 7; // Allow larger programs with extra fees
    v42.max_absolute_total_arg_len = 16_384; // We _could_ make this as high as 16*4k
    v42.per_byte_txn_surcharge = 100; // Each charged byte adds 0.000100 of min fee
    v42.enable_select_f128 = true;
    if version == CONSENSUS_V42 {
        return Some(v42);
    }

    // ── future ──────────────────────────────────────────────────
    // go: vFuture := v42; vFuture.LogicSigVersion = 14 (commit 88fe542f3
    // moved vFuture's onward from v41 to v42 and bumped LogicSigVersion
    // again for the next in-development AVM version).
    let mut v_future = v42.clone();
    v_future.logic_sig_version = 14;
    if version == CONSENSUS_FUTURE {
        return Some(v_future);
    }

    // ── Alpha versions ──────────────────────────────────────────
    // alpha1 inherits from v32 with different filter timeout / block size
    if version == CONSENSUS_ALPHA1 {
        let mut alpha =
            consensus_params_for_version(CONSENSUS_V32).expect("V32 must be constructible");
        alpha.agreement_filter_timeout_period0 = Duration::from_secs(2);
        alpha.max_txn_bytes_per_block = 5_000_000;
        return Some(alpha);
    }

    // alpha2 inherits from alpha1
    if version == CONSENSUS_ALPHA2 {
        let mut alpha =
            consensus_params_for_version(CONSENSUS_ALPHA1).expect("alpha1 must be constructible");
        alpha.agreement_filter_timeout_period0 = Duration::from_millis(3500);
        alpha.max_txn_bytes_per_block = 5 * 1024 * 1024;
        return Some(alpha);
    }

    // alpha3 same as v33
    if version == CONSENSUS_ALPHA3 {
        return consensus_params_for_version(CONSENSUS_V33);
    }

    // alpha4 same as v34
    if version == CONSENSUS_ALPHA4 {
        return consensus_params_for_version(CONSENSUS_V34);
    }

    // alpha5 same as v36
    if version == CONSENSUS_ALPHA5 {
        return consensus_params_for_version(CONSENSUS_V36);
    }

    // ── FNet versions ───────────────────────────────────────────
    // go: config/consensus.go (v5.0.0-stable), commit 189914a64 ("FNet: add
    // fnet1..4 consensus versions, genesis, and docker (#6675)"). Modeled
    // for table-completeness parity only; algod-rust does not join FNet.
    //
    // fnet1 is the FNet genesis protocol: v39 base, LogicSigVersion bumped to
    // 11 (TEAL v11), plus FNet-tuned payouts/bonus overrides.
    if version == CONSENSUS_VFNET1 {
        let mut fnet1 =
            consensus_params_for_version(CONSENSUS_V39).expect("v39 must be constructible");
        fnet1.logic_sig_version = 11;
        fnet1.payouts_enabled = true;
        fnet1.payouts_percent = 75;
        fnet1.payouts_go_online_fee = 2_000_000; // 2 algos
        fnet1.payouts_min_balance = 30_000_000_000; // 30,000 algos
        fnet1.payouts_max_balance = 70_000_000_000_000; // 70M algos
        fnet1.payouts_max_mark_absent = 32;
        fnet1.payouts_challenge_interval = 1_000;
        fnet1.payouts_challenge_grace_period = 200;
        fnet1.payouts_challenge_bits = 5;
        fnet1.bonus_base_amount = 10_000_000; // 10 algos
        fnet1.bonus_decay_interval = 250_000;
        return Some(fnet1);
    }

    // fnet2 guards against a block-opcode change the fnet1 client did not
    // support; no parameter change from fnet1.
    if version == CONSENSUS_VFNET2 {
        return consensus_params_for_version(CONSENSUS_VFNET1);
    }

    // fnet3 disables challenges (no heartbeats yet, so challenged accounts
    // were being evicted); otherwise same as fnet2.
    if version == CONSENSUS_VFNET3 {
        let mut fnet3 =
            consensus_params_for_version(CONSENSUS_VFNET2).expect("fnet2 must be constructible");
        fnet3.payouts_challenge_interval = 0;
        return Some(fnet3);
    }

    // fnet4 re-enables challenges (back to fnet1's parameters) ahead of the
    // upgrade path to v40.
    if version == CONSENSUS_VFNET4 {
        return consensus_params_for_version(CONSENSUS_VFNET1);
    }

    // Unknown version
    None
}

// ── Configurable consensus.json load/merge/save ─────────────────────
//
// Mirrors go-algorand's `PreloadConfigurableConsensusProtocols` /
// `LoadConfigurableConsensusProtocols` / `SaveConfigurableConsensus`
// (`config/config.go`) and `ConsensusProtocols.Merge` (`config/consensus.go`
// ~line 858): an operator may drop a `consensus.json` file into a node's
// data directory to override the built-in per-version consensus parameters.
// A missing file is not an error (silent fallback to the built-in table); a
// present-but-malformed file is. Each override entry either deletes its
// version (when `ApprovedUpgrades` is absent/null) or replaces the *entire*
// `ConsensusParams` struct for that version wholesale (never a field-by-field
// merge within one version).

/// go-algorand's `time.Duration` has no custom `MarshalJSON`, so it encodes
/// as a bare JSON integer of nanoseconds via the default `encoding/json`
/// int64 path. This reproduces that on both sides so the same file
/// deserializes identically in Go and Rust.
mod duration_nanos {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(value.as_nanos() as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        let nanos = u64::deserialize(deserializer)?;
        Ok(Duration::from_nanos(nanos))
    }
}

/// JSON shape of go-algorand's `config.Payouts` (`ProposerPayoutRules`),
/// embedded in `ConsensusParams` as the nested `"Payouts"` object.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct PayoutsOverride {
    pub enabled: bool,
    pub go_online_fee: u64,
    pub percent: u64,
    pub min_balance: u64,
    pub max_balance: u64,
    pub max_mark_absent: usize,
    pub challenge_interval: u64,
    pub challenge_grace_period: u64,
    pub challenge_bits: u32,
}

/// JSON shape of go-algorand's `config.BonusPlan`, embedded in
/// `ConsensusParams` as the nested `"Bonus"` object.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct BonusOverride {
    pub base_round: u64,
    pub base_amount: u64,
    pub decay_interval: u64,
}

/// `serde(default = "default_true")` helper for
/// [`ConsensusParamsOverride`]'s `enable_fee_pooling`/
/// `enable_logicsig_size_pooling` fields -- see their doc comments and
/// [`ConsensusParamsOverride`]'s own doc comment for why a non-zero default
/// is required for these two fields specifically.
fn default_true() -> bool {
    true
}

/// JSON-deserializable mirror of go-algorand's `config.ConsensusParams`
/// (`config/consensus.go`), used only for parsing/writing a
/// `consensus.json` override entry. Field names match go's JSON tags
/// (go's default `encoding/json` struct-field naming: the exported Go field
/// name verbatim), so the exact same file deserializes on both sides.
///
/// Every field carries the container-level `#[serde(default)]`: a JSON key
/// absent from the file takes this struct's (zero-valued) `Default`, exactly
/// matching Go's `json.Unmarshal`-into-a-zero-value-struct semantics — which
/// matters because `Merge`'s "otherwise" branch (see
/// [`merge_consensus_protocols`]) replaces a version's *entire*
/// `ConsensusParams`, not just the fields the file happens to set.
///
/// Two fields algod-rust models on `ConsensusParams` (`max_log_size`,
/// `max_log_calls`) are deliberately absent here: they mirror the AVM's
/// `logic.Bounds` (`data/transactions/logic/eval.go`), not go's
/// `config.ConsensusParams` — go-algorand's own `consensus.json` can never
/// set them, so [`ConsensusParamsOverride::to_consensus_params`] always fills
/// them with the flat defaults every built-in version already uses.
///
/// Unknown JSON keys (fields go-algorand's struct has that algod-rust
/// doesn't yet model) are silently ignored rather than rejected — this is
/// not `deny_unknown_fields` — so a real go-algorand-authored file that also
/// sets fields algod-rust doesn't yet track still loads instead of erroring.
///
/// `enable_fee_pooling` and `enable_logicsig_size_pooling` are the one
/// deliberate exception to the zero-valued-default rule above: go-algorand
/// removed both fields from its own live `ConsensusParams` struct once they
/// became permanently on (v28+ / v40+ respectively), so a real
/// go-algorand-authored `consensus.json` (e.g. from
/// `tools/vfuture-consensus-override`) never carries either key. Defaulting
/// them to Rust's zero value (`false`) would silently disable both features
/// for every version this repo targets whenever such a file overrides that
/// version — found live during issue #814's mixed-cluster verification.
/// Both carry an explicit `#[serde(default = "default_true")]` instead.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ConsensusParamsOverride {
    pub logic_sig_version: u64,
    pub logic_sig_max_size: u64,
    pub max_absolute_logic_sig_program_size: u64,
    pub logic_sig_max_cost: u64,
    pub max_app_program_cost: u64,
    pub min_balance: u64,
    pub min_txn_fee: u64,
    pub max_txn_life: u64,
    pub max_txn_note_bytes: usize,
    pub max_tx_group_size: usize,
    pub max_txn_bytes_per_block: u64,
    pub max_absolute_txn_note_bytes: usize,
    pub max_absolute_extra_program_pages: u32,
    pub max_absolute_total_arg_len: usize,
    pub per_byte_txn_surcharge: u64,
    /// Go's own `config.ConsensusParams` dropped `EnableFeePooling` once fee
    /// pooling became permanently on (v28+), so a `consensus.json` built by
    /// marshaling a real go-algorand `ConsensusParams` (e.g.
    /// `tools/vfuture-consensus-override`) never carries this key. Default
    /// to `true` rather than the container's zero-value default so such a
    /// full-struct override doesn't silently disable fee pooling on every
    /// version this repo targets (all >= v28) -- see issue #814's
    /// live-verification session.
    #[serde(default = "default_true")]
    pub enable_fee_pooling: bool,
    pub support_tx_groups: bool,
    pub support_transaction_leases: bool,
    pub fix_transaction_leases: bool,
    pub support_rekeying: bool,
    /// Go: `Heartbeat` (not `EnableHeartbeat`).
    #[serde(rename = "Heartbeat")]
    pub enable_heartbeat: bool,
    pub enforce_auth_addr_sender_diff: bool,
    pub load_tracking: bool,
    pub app_size_updates: bool,
    pub allow_zero_local_app_ref: bool,
    #[serde(rename = "EnablePQSchemeFalcon1024")]
    pub enable_pq_scheme_falcon1024: bool,
    pub enable_select_f128: bool,
    /// Same rationale as `enable_fee_pooling` above: go removed
    /// `EnableLogicSigSizePooling` from its live struct once it became
    /// permanently on (v40+), so it is never present in a real
    /// go-algorand-authored `consensus.json`. Default to `true`.
    #[serde(rename = "EnableLogicSigSizePooling", default = "default_true")]
    pub enable_logicsig_size_pooling: bool,
    #[serde(rename = "EnableLogicSigCostPooling")]
    pub enable_logicsig_cost_pooling: bool,
    pub enable_app_cost_pooling: bool,
    pub enable_inner_transaction_pooling: bool,
    pub application: bool,
    pub asset: bool,
    pub max_inner_transactions: usize,
    pub min_inner_appl_version: u64,
    pub max_app_key_len: usize,
    pub max_app_bytes_value_len: usize,
    pub max_app_sum_key_value_lens: usize,
    pub max_extra_app_program_pages: u32,
    pub max_app_program_len: usize,
    pub max_app_total_program_len: usize,
    pub max_global_schema_entries: u64,
    pub max_local_schema_entries: u64,
    pub max_app_args: usize,
    pub max_app_total_arg_len: usize,
    pub max_app_txn_accounts: usize,
    pub max_app_txn_foreign_apps: usize,
    pub max_app_txn_foreign_assets: usize,
    pub max_app_total_txn_references: usize,
    pub max_app_access: usize,
    pub max_box_size: u64,
    pub bytes_per_box_reference: u64,
    pub max_app_box_references: usize,
    pub enable_box_ref_name_error: bool,
    pub app_flat_params_min_balance: u64,
    pub app_flat_opt_in_min_balance: u64,
    pub schema_min_balance_per_entry: u64,
    pub schema_uint_min_balance: u64,
    pub schema_bytes_min_balance: u64,
    pub box_flat_min_balance: u64,
    pub box_byte_min_balance: u64,
    pub maximum_minimum_balance: u64,
    pub max_assets_per_account: u32,
    pub deeper_block_header_history: u64,
    pub reward_unit: u64,
    pub rewards_rate_refresh_interval: u64,
    pub max_timestamp_increment: i64,
    pub payset_commit: u8,
    #[serde(rename = "EnableSHA256TxnCommitmentHeader")]
    pub enable_sha256_txn_commitment_header: bool,
    pub enable_sha512_block_hash: bool,
    pub require_genesis_hash: bool,
    pub support_genesis_hash: bool,
    pub max_apps_created: usize,
    pub max_apps_opted_in: usize,
    pub max_keyreg_valid_period: u64,
    pub enable_keyreg_coherency_check: bool,
    pub enable_state_proof_keyreg_check: bool,
    pub state_proof_interval: u64,
    pub state_proof_voters_lookback: u64,
    pub state_proof_block_hash_in_light_header: bool,
    pub state_proof_weight_threshold: u32,
    pub state_proof_strength_target: u64,
    pub isolate_clear_state: bool,
    #[serde(rename = "MaxAssetURLBytes")]
    pub max_asset_url_bytes: usize,
    pub max_asset_name_bytes: usize,
    pub max_asset_unit_name_bytes: usize,
    pub max_asset_decimals: u32,
    pub max_proposed_expired_online_accounts: usize,
    #[serde(rename = "Payouts")]
    pub payouts: PayoutsOverride,
    #[serde(rename = "Bonus")]
    pub bonus: BonusOverride,
    pub support_become_non_participating_transactions: bool,
    pub enable_app_versioning: bool,
    pub num_proposers: u64,
    pub soft_committee_size: u64,
    pub soft_committee_threshold: u64,
    pub cert_committee_size: u64,
    pub cert_committee_threshold: u64,
    pub next_committee_size: u64,
    pub next_committee_threshold: u64,
    pub late_committee_size: u64,
    pub late_committee_threshold: u64,
    pub redo_committee_size: u64,
    pub redo_committee_threshold: u64,
    pub down_committee_size: u64,
    pub down_committee_threshold: u64,
    #[serde(with = "duration_nanos")]
    pub agreement_filter_timeout: Duration,
    #[serde(with = "duration_nanos")]
    pub agreement_filter_timeout_period0: Duration,
    #[serde(with = "duration_nanos")]
    pub agreement_deadline_timeout_period0: Duration,
    #[serde(with = "duration_nanos")]
    pub fast_recovery_lambda: Duration,
    pub seed_lookback: u64,
    pub seed_refresh_interval: u64,
    pub max_bal_lookback: u64,
    pub default_key_dilution: u64,
    pub credential_domain_separation_enabled: bool,
    pub dynamic_filter_timeout: bool,
    pub exclude_expired_circulation: bool,
    /// `nil`/absent means "delete this version" per
    /// [`merge_consensus_protocols`]; `{}` means "replace this version, no
    /// outbound upgrade proposal of its own" — the distinction is exactly
    /// go's `consensusParams.ApprovedUpgrades == nil` check
    /// (`config/consensus.go`), which is why this stays `Option` rather than
    /// defaulting to an empty map.
    #[serde(rename = "ApprovedUpgrades")]
    pub approved_upgrades: Option<HashMap<String, u64>>,
    pub upgrade_vote_rounds: u64,
    pub upgrade_threshold: u64,
    pub default_upgrade_wait_rounds: u64,
    pub min_upgrade_wait_rounds: u64,
    pub max_upgrade_wait_rounds: u64,
    pub pending_residue_rewards: bool,
    pub initial_rewards_rate_calculation: bool,
    pub rewards_calculation_fix: bool,
    #[serde(rename = "UnifyInnerTxIDs")]
    pub unify_inner_tx_ids: bool,
    pub unfunded_senders: bool,
    #[serde(rename = "EnablePrecheckECDSACurve")]
    pub enable_precheck_ecdsa_curve: bool,
    pub app_forbid_low_resources: bool,
    pub state_proof_top_voters: u64,
    pub logic_sig_msig: bool,
    /// Go: `LogicSigLMsig` (capital `M`).
    #[serde(rename = "LogicSigLMsig")]
    pub logic_sig_lmsig: bool,
    pub enable_bare_budget_error: bool,
    pub state_proof_max_recovery_intervals: u64,
    pub state_proof_use_tracker_verification: bool,
    pub catchpoint_lookback: u64,
    pub enable_ledger_data_update_round: bool,
    /// Go: `EnableCatchpointsWithSPContexts` (capital `SP`).
    #[serde(rename = "EnableCatchpointsWithSPContexts")]
    pub enable_catchpoints_with_sp_contexts: bool,
    pub enable_catchpoints_with_online_accounts: bool,
}

impl ConsensusParamsOverride {
    /// Convert a fully-specified override entry into the internal
    /// `ConsensusParams` representation used everywhere else in the
    /// codebase. Every field is taken verbatim (including Go-zero-value
    /// defaults for anything the file omitted) because [`merge_consensus_protocols`]'s
    /// "otherwise" branch replaces the whole struct, not just the fields the
    /// file happened to set.
    ///
    /// go-algorand's `ApprovedUpgrades` is a `map[ConsensusVersion]uint64`
    /// (arbitrarily many target versions); algod-rust models at most one
    /// outbound upgrade proposal per version (`ConsensusParams::approved_upgrade`),
    /// matching every entry go-algorand's own version history has ever
    /// actually populated. If an override supplies more than one entry, the
    /// lexicographically-smallest target-version name is kept — a documented
    /// limitation of this internal representation, not a silent gap (no
    /// known consensus.json, including go-algorand's own, has ever needed
    /// more than one).
    fn to_consensus_params(&self) -> ConsensusParams {
        let approved_upgrade = self
            .approved_upgrades
            .as_ref()
            .and_then(|targets| targets.iter().min_by_key(|(version, _)| version.as_str()))
            .map(|(version, &delay)| (static_version_name(version), delay));

        ConsensusParams {
            logic_sig_version: self.logic_sig_version,
            logic_sig_max_size: self.logic_sig_max_size,
            max_absolute_logic_sig_program_size: self.max_absolute_logic_sig_program_size,
            logic_sig_max_cost: self.logic_sig_max_cost,
            max_app_program_cost: self.max_app_program_cost,
            min_balance: self.min_balance,
            min_txn_fee: self.min_txn_fee,
            max_txn_life: self.max_txn_life,
            max_txn_note_bytes: self.max_txn_note_bytes,
            max_tx_group_size: self.max_tx_group_size,
            max_txn_bytes_per_block: self.max_txn_bytes_per_block,
            max_absolute_txn_note_bytes: self.max_absolute_txn_note_bytes,
            max_absolute_extra_program_pages: self.max_absolute_extra_program_pages,
            max_absolute_total_arg_len: self.max_absolute_total_arg_len,
            per_byte_txn_surcharge: self.per_byte_txn_surcharge,
            enable_fee_pooling: self.enable_fee_pooling,
            support_tx_groups: self.support_tx_groups,
            support_transaction_leases: self.support_transaction_leases,
            fix_transaction_leases: self.fix_transaction_leases,
            support_rekeying: self.support_rekeying,
            enable_heartbeat: self.enable_heartbeat,
            enforce_auth_addr_sender_diff: self.enforce_auth_addr_sender_diff,
            load_tracking: self.load_tracking,
            app_size_updates: self.app_size_updates,
            allow_zero_local_app_ref: self.allow_zero_local_app_ref,
            enable_pq_scheme_falcon1024: self.enable_pq_scheme_falcon1024,
            enable_select_f128: self.enable_select_f128,
            enable_logicsig_size_pooling: self.enable_logicsig_size_pooling,
            enable_logicsig_cost_pooling: self.enable_logicsig_cost_pooling,
            enable_app_cost_pooling: self.enable_app_cost_pooling,
            enable_inner_transaction_pooling: self.enable_inner_transaction_pooling,
            application: self.application,
            asset: self.asset,
            max_inner_transactions: self.max_inner_transactions,
            min_inner_appl_version: self.min_inner_appl_version,
            max_app_key_len: self.max_app_key_len,
            max_app_bytes_value_len: self.max_app_bytes_value_len,
            max_app_sum_key_value_lens: self.max_app_sum_key_value_lens,
            max_extra_app_program_pages: self.max_extra_app_program_pages,
            max_app_program_len: self.max_app_program_len,
            max_app_total_program_len: self.max_app_total_program_len,
            max_global_schema_entries: self.max_global_schema_entries,
            max_local_schema_entries: self.max_local_schema_entries,
            max_app_args: self.max_app_args,
            max_app_total_arg_len: self.max_app_total_arg_len,
            max_app_txn_accounts: self.max_app_txn_accounts,
            max_app_txn_foreign_apps: self.max_app_txn_foreign_apps,
            max_app_txn_foreign_assets: self.max_app_txn_foreign_assets,
            max_app_total_txn_references: self.max_app_total_txn_references,
            max_app_access: self.max_app_access,
            max_box_size: self.max_box_size,
            bytes_per_box_reference: self.bytes_per_box_reference,
            max_app_box_references: self.max_app_box_references,
            enable_box_ref_name_error: self.enable_box_ref_name_error,
            app_flat_params_min_balance: self.app_flat_params_min_balance,
            app_flat_opt_in_min_balance: self.app_flat_opt_in_min_balance,
            schema_min_balance_per_entry: self.schema_min_balance_per_entry,
            schema_uint_min_balance: self.schema_uint_min_balance,
            schema_bytes_min_balance: self.schema_bytes_min_balance,
            box_flat_min_balance: self.box_flat_min_balance,
            box_byte_min_balance: self.box_byte_min_balance,
            maximum_minimum_balance: self.maximum_minimum_balance,
            max_assets_per_account: self.max_assets_per_account,
            // Not part of go's `config.ConsensusParams` JSON shape — see the
            // struct doc comment.
            max_log_size: 1024,
            max_log_calls: 32,
            deeper_block_header_history: self.deeper_block_header_history,
            reward_unit: self.reward_unit,
            rewards_rate_refresh_interval: self.rewards_rate_refresh_interval,
            max_timestamp_increment: self.max_timestamp_increment,
            payset_commit: self.payset_commit,
            enable_sha256_txn_commitment_header: self.enable_sha256_txn_commitment_header,
            enable_sha512_block_hash: self.enable_sha512_block_hash,
            require_genesis_hash: self.require_genesis_hash,
            support_genesis_hash: self.support_genesis_hash,
            max_apps_created: self.max_apps_created,
            max_apps_opted_in: self.max_apps_opted_in,
            max_keyreg_valid_period: self.max_keyreg_valid_period,
            enable_keyreg_coherency_check: self.enable_keyreg_coherency_check,
            enable_state_proof_keyreg_check: self.enable_state_proof_keyreg_check,
            state_proof_interval: self.state_proof_interval,
            state_proof_voters_lookback: self.state_proof_voters_lookback,
            state_proof_block_hash_in_light_header: self.state_proof_block_hash_in_light_header,
            state_proof_weight_threshold: self.state_proof_weight_threshold,
            state_proof_strength_target: self.state_proof_strength_target,
            isolate_clear_state: self.isolate_clear_state,
            max_asset_url_bytes: self.max_asset_url_bytes,
            max_asset_name_bytes: self.max_asset_name_bytes,
            max_asset_unit_name_bytes: self.max_asset_unit_name_bytes,
            max_asset_decimals: self.max_asset_decimals,
            max_proposed_expired_online_accounts: self.max_proposed_expired_online_accounts,
            payouts_enabled: self.payouts.enabled,
            payouts_go_online_fee: self.payouts.go_online_fee,
            payouts_percent: self.payouts.percent,
            payouts_min_balance: self.payouts.min_balance,
            payouts_max_balance: self.payouts.max_balance,
            payouts_max_mark_absent: self.payouts.max_mark_absent,
            payouts_challenge_interval: self.payouts.challenge_interval,
            payouts_challenge_grace_period: self.payouts.challenge_grace_period,
            payouts_challenge_bits: self.payouts.challenge_bits,
            bonus_base_round: self.bonus.base_round,
            bonus_base_amount: self.bonus.base_amount,
            bonus_decay_interval: self.bonus.decay_interval,
            support_become_non_participating_transactions: self
                .support_become_non_participating_transactions,
            enable_app_versioning: self.enable_app_versioning,
            num_proposers: self.num_proposers,
            soft_committee_size: self.soft_committee_size,
            soft_committee_threshold: self.soft_committee_threshold,
            cert_committee_size: self.cert_committee_size,
            cert_committee_threshold: self.cert_committee_threshold,
            next_committee_size: self.next_committee_size,
            next_committee_threshold: self.next_committee_threshold,
            late_committee_size: self.late_committee_size,
            late_committee_threshold: self.late_committee_threshold,
            redo_committee_size: self.redo_committee_size,
            redo_committee_threshold: self.redo_committee_threshold,
            down_committee_size: self.down_committee_size,
            down_committee_threshold: self.down_committee_threshold,
            agreement_filter_timeout: self.agreement_filter_timeout,
            agreement_filter_timeout_period0: self.agreement_filter_timeout_period0,
            agreement_deadline_timeout_period0: self.agreement_deadline_timeout_period0,
            fast_recovery_lambda: self.fast_recovery_lambda,
            seed_lookback: self.seed_lookback,
            seed_refresh_interval: self.seed_refresh_interval,
            max_bal_lookback: self.max_bal_lookback,
            default_key_dilution: self.default_key_dilution,
            credential_domain_separation_enabled: self.credential_domain_separation_enabled,
            dynamic_filter_timeout: self.dynamic_filter_timeout,
            exclude_expired_circulation: self.exclude_expired_circulation,
            approved_upgrade,
            upgrade_vote_rounds: self.upgrade_vote_rounds,
            upgrade_threshold: self.upgrade_threshold,
            default_upgrade_wait_rounds: self.default_upgrade_wait_rounds,
            min_upgrade_wait_rounds: self.min_upgrade_wait_rounds,
            max_upgrade_wait_rounds: self.max_upgrade_wait_rounds,
            pending_residue_rewards: self.pending_residue_rewards,
            initial_rewards_rate_calculation: self.initial_rewards_rate_calculation,
            rewards_calculation_fix: self.rewards_calculation_fix,
            unify_inner_tx_ids: self.unify_inner_tx_ids,
            unfunded_senders: self.unfunded_senders,
            enable_precheck_ecdsa_curve: self.enable_precheck_ecdsa_curve,
            app_forbid_low_resources: self.app_forbid_low_resources,
            state_proof_top_voters: self.state_proof_top_voters,
            logic_sig_msig: self.logic_sig_msig,
            logic_sig_lmsig: self.logic_sig_lmsig,
            enable_bare_budget_error: self.enable_bare_budget_error,
            state_proof_max_recovery_intervals: self.state_proof_max_recovery_intervals,
            state_proof_use_tracker_verification: self.state_proof_use_tracker_verification,
            catchpoint_lookback: self.catchpoint_lookback,
            enable_ledger_data_update_round: self.enable_ledger_data_update_round,
            enable_catchpoints_with_sp_contexts: self.enable_catchpoints_with_sp_contexts,
            enable_catchpoints_with_online_accounts: self.enable_catchpoints_with_online_accounts,
        }
    }
}

/// The `consensus.json` file shape: a map from consensus-version string to
/// override entry (Go: `config.ConsensusProtocols`, a
/// `map[protocol.ConsensusVersion]config.ConsensusParams`).
pub type ConsensusOverrides = HashMap<String, ConsensusParamsOverride>;

/// Filename go-algorand looks for under a node's data directory to load
/// configurable consensus-parameter overrides (Go:
/// `config.ConfigurableConsensusProtocolsFilename`, `config/config.go`).
pub const CONFIGURABLE_CONSENSUS_PROTOCOLS_FILENAME: &str = "consensus.json";

/// Resolve a JSON-supplied target-version string to a `&'static str`: reuse
/// the matching compile-time constant when the name is a known protocol
/// version, else leak the owned string. `consensus.json` is loaded at most
/// once per node lifetime (startup), so the leak is bounded by the (small,
/// finite) number of distinct override target-version names a node is ever
/// configured with — the same "load once, live forever" lifetime the
/// compile-time table already assumes for `ConsensusParams::approved_upgrade`.
fn static_version_name(name: &str) -> &'static str {
    if let Some(&known) = KNOWN_PROTOCOL_VERSIONS.iter().find(|&&k| k == name) {
        known
    } else {
        Box::leak(name.to_owned().into_boxed_str())
    }
}

/// Build the compile-time built-in consensus-parameter table for every
/// version algod-rust knows, keyed by version string. Rust analog of
/// go-algorand's package-level `Consensus` map, freshly populated by
/// `initConsensusProtocols()` (`config/consensus.go`).
pub fn built_in_consensus_protocols() -> HashMap<String, ConsensusParams> {
    KNOWN_PROTOCOL_VERSIONS
        .iter()
        .filter_map(|&version| {
            consensus_params_for_version(version).map(|params| (version.to_string(), params))
        })
        .collect()
}

/// Process-global, write-once-at-startup consensus-parameter override
/// registry (issue #762). A fixed `HashMap<String, ConsensusParams>` (the
/// full merged table `preload_configurable_consensus_protocols` already
/// produces) is deliberately *not* what's stored here: instead this stores
/// only the *diff* against the compile-time built-in table --
/// `Some(params)` for a version an override replaces or newly adds, `None`
/// for a version an override deletes (mirroring
/// [`merge_consensus_protocols`]'s "absent `ApprovedUpgrades` deletes the
/// version" semantics: it becomes unknown, not silently falls back to its
/// old built-in definition).
///
/// Storing only the diff -- rather than the whole merged table -- means a
/// version the loaded `consensus.json` never mentions is completely
/// unaffected by installing this registry: [`consensus_params_for_version`]
/// only ever consults this map for a version key present in it, falling
/// through to the ordinary compile-time computation for everything else.
/// This is what keeps the "before this global is populated... zero behavior
/// change" invariant honest even *after* population, for every version a
/// custom `consensus.json` didn't touch -- which is the common case (a
/// private network typically overrides only its current protocol version).
static CONSENSUS_OVERRIDES: std::sync::OnceLock<HashMap<String, Option<ConsensusParams>>> =
    std::sync::OnceLock::new();

/// Install this node's consensus-parameter overrides -- loaded from
/// `<data_dir>/consensus.json` at startup and merged onto the built-in table
/// by [`preload_configurable_consensus_protocols`] -- as the process-global
/// source [`consensus_params_for_version`] consults before falling back to
/// the compile-time built-in table. This is what threads a custom
/// `consensus.json` through all ~57 call sites of
/// `consensus_params_for_version` across ledger apply, AVM evaluation,
/// agreement/committee logic, REST API handlers, and simulation (issue
/// #762) -- every one of them already calls that single function, so fixing
/// it here is enough; no call site itself needs to change.
///
/// `merged` is exactly the return value of
/// [`preload_configurable_consensus_protocols`] (or, equivalently,
/// [`merge_consensus_protocols`]'s output): the built-in table with any
/// loaded overrides already merged on top. This function diffs `merged`
/// against a *fresh* [`built_in_consensus_protocols`] call to recover which
/// versions the load actually touched (replaced, added, or deleted) --
/// reusing `merge_consensus_protocols`'s already-correct wholesale-replace/
/// delete/dangling-`approved_upgrade`-pruning semantics rather than
/// re-implementing them, and (critically) so that a version the override
/// never mentions is not re-recorded here at all, leaving
/// [`consensus_params_for_version`] behaviorally untouched for it.
///
/// # Write-once / thread-safety
///
/// Must be called at most once, early in `bin/algod-rust`'s single startup
/// thread, strictly before any ledger/AVM/agreement consensus-evaluation
/// logic runs on any thread. A second call (e.g. an accidental double
/// invocation) is silently ignored rather than panicking or clobbering the
/// first: a write-once-then-read-only global must never partially change an
/// already-running node's view of consensus parameters mid-flight, and a
/// silent second-call no-op is safer for a consensus-critical global than a
/// panic that would take the whole node down over what is, at worst, a
/// harmless redundant call. `OnceLock` guarantees the read side
/// ([`consensus_params_for_version`]) never observes a partially-written
/// map from any thread, without needing a lock on the read path.
pub fn install_consensus_overrides(merged: &HashMap<String, ConsensusParams>) {
    // Computed before any lookup could possibly observe a partially-applied
    // registry (`CONSENSUS_OVERRIDES` is not yet set while this runs), so
    // every `consensus_params_for_version` call `built_in_consensus_protocols`
    // makes here still resolves purely from the compile-time table.
    let built_in = built_in_consensus_protocols();

    let mut diff: HashMap<String, Option<ConsensusParams>> = HashMap::new();
    for (version, params) in merged {
        if built_in.get(version) != Some(params) {
            diff.insert(version.clone(), Some(params.clone()));
        }
    }
    for version in built_in.keys() {
        if !merged.contains_key(version) {
            diff.insert(version.clone(), None);
        }
    }

    // Ignore the error (registry already installed): see write-once note above.
    let _ = CONSENSUS_OVERRIDES.set(diff);
}

/// Merge configurable `consensus.json` overrides onto a base consensus
/// table, mirroring go-algorand's `ConsensusProtocols.Merge`
/// (`config/consensus.go` ~line 858): per override entry, an absent/null
/// `ApprovedUpgrades` deletes that version from the result (and prunes any
/// other version's `approved_upgrade` that pointed at the deleted version);
/// otherwise the version is added/replaced *wholesale* — this is a
/// whole-struct replace-per-version-key, not a field-by-field merge within
/// one version's params.
pub fn merge_consensus_protocols(
    base: HashMap<String, ConsensusParams>,
    overrides: ConsensusOverrides,
) -> HashMap<String, ConsensusParams> {
    let mut merged = base;

    for (version, params) in overrides {
        match params.approved_upgrades {
            None => {
                merged.remove(&version);
                for other in merged.values_mut() {
                    if other.approved_upgrade.map(|(target, _)| target) == Some(version.as_str()) {
                        other.approved_upgrade = None;
                    }
                }
            }
            Some(_) => {
                let resolved = params.to_consensus_params();
                merged.insert(version, resolved);
            }
        }
    }

    merged
}

/// Load `<data_dir>/consensus.json` (if present) and merge it onto the
/// built-in consensus table, mirroring go-algorand's
/// `PreloadConfigurableConsensusProtocols` (`config/config.go` ~line 336): a
/// missing file is not an error (falls back to the built-in table
/// unchanged); a present-but-malformed file surfaces as a real error.
pub fn preload_configurable_consensus_protocols(
    data_dir: &Path,
) -> algo_error::Result<HashMap<String, ConsensusParams>> {
    let path = data_dir.join(CONFIGURABLE_CONSENSUS_PROTOCOLS_FILENAME);
    let base = built_in_consensus_protocols();

    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(base),
        Err(e) => {
            return Err(algo_error::AlgoError::Config(format!(
                "reading {}: {e}",
                path.display()
            )))
        }
    };

    let overrides: ConsensusOverrides = serde_json::from_str(&contents)
        .map_err(|e| algo_error::AlgoError::Config(format!("parsing {}: {e}", path.display())))?;

    Ok(merge_consensus_protocols(base, overrides))
}

/// Write (or, for an empty override map, delete) `<data_dir>/consensus.json`,
/// mirroring go-algorand's `SaveConfigurableConsensus` (`config/config.go`
/// ~line 314).
pub fn save_configurable_consensus(
    data_dir: &Path,
    overrides: &ConsensusOverrides,
) -> algo_error::Result<()> {
    let path = data_dir.join(CONFIGURABLE_CONSENSUS_PROTOCOLS_FILENAME);

    if overrides.is_empty() {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(algo_error::AlgoError::Io(e)),
        };
    }

    let encoded = serde_json::to_vec_pretty(overrides)
        .map_err(|e| algo_error::AlgoError::Config(format!("encoding consensus.json: {e}")))?;
    std::fs::write(&path, encoded).map_err(algo_error::AlgoError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v7_base_values() {
        let p = consensus_params_for_version(CONSENSUS_V7).unwrap();
        assert_eq!(p.min_balance, 10_000);
        assert_eq!(p.min_txn_fee, 1_000);
        assert_eq!(p.max_txn_life, 1_000);
        assert_eq!(p.max_txn_note_bytes, 1_024);
        assert_eq!(p.max_tx_group_size, 1);
        assert_eq!(p.max_txn_bytes_per_block, 1_000_000);
        assert_eq!(p.logic_sig_version, 0);
        assert!(!p.support_tx_groups);
        assert!(!p.support_transaction_leases);
        assert!(!p.support_rekeying);
        assert!(!p.enable_fee_pooling);
        assert!(!p.application);
        assert!(!p.asset);
    }

    #[test]
    fn test_v9_min_balance() {
        let p = consensus_params_for_version(CONSENSUS_V9).unwrap();
        assert_eq!(p.min_balance, 100_000);
    }

    #[test]
    fn test_v18_features() {
        let p = consensus_params_for_version(CONSENSUS_V18).unwrap();
        assert!(p.asset);
        assert!(p.support_tx_groups);
        assert_eq!(p.max_tx_group_size, 16);
        assert!(p.support_transaction_leases);
        assert_eq!(p.logic_sig_version, 1);
        assert_eq!(p.logic_sig_max_size, 1000);
        assert_eq!(p.logic_sig_max_cost, 20_000);
        assert_eq!(p.max_assets_per_account, 1000);
    }

    #[test]
    fn test_v24_apps() {
        let p = consensus_params_for_version(CONSENSUS_V24).unwrap();
        assert!(p.application);
        assert!(p.support_rekeying);
        assert_eq!(p.logic_sig_version, 2);
        assert_eq!(p.max_app_args, 16);
        assert_eq!(p.max_app_program_len, 1024);
        assert_eq!(p.max_app_key_len, 64);
        assert_eq!(p.max_app_program_cost, 700);
        assert_eq!(p.schema_min_balance_per_entry, 25_000);
        assert_eq!(p.schema_uint_min_balance, 3_500);
        assert_eq!(p.schema_bytes_min_balance, 25_000);
    }

    #[test]
    fn test_v28_fee_pooling() {
        let p = consensus_params_for_version(CONSENSUS_V28).unwrap();
        assert!(p.enable_fee_pooling);
        assert_eq!(p.logic_sig_version, 4);
        assert_eq!(p.max_extra_app_program_pages, 3);
        assert_eq!(p.max_absolute_extra_program_pages, 3);
        assert_eq!(p.max_app_program_len, 2048);
        assert!(p.enable_keyreg_coherency_check);
    }

    #[test]
    fn test_v30_inner_txns() {
        let p = consensus_params_for_version(CONSENSUS_V30).unwrap();
        assert_eq!(p.max_inner_transactions, 16);
        assert!(p.enable_app_cost_pooling);
        assert_eq!(p.logic_sig_version, 5);
    }

    #[test]
    fn test_v31_features() {
        let p = consensus_params_for_version(CONSENSUS_V31).unwrap();
        assert!(p.enable_inner_transaction_pooling);
        assert!(p.isolate_clear_state);
        assert_eq!(p.logic_sig_version, 6);
        assert_eq!(p.max_keyreg_valid_period, 256 * (1 << 16) - 1);
        assert_eq!(p.max_proposed_expired_online_accounts, 32);
    }

    #[test]
    fn test_v32_unlimited() {
        let p = consensus_params_for_version(CONSENSUS_V32).unwrap();
        assert_eq!(p.max_assets_per_account, 0);
        assert_eq!(p.max_apps_created, 0);
        assert_eq!(p.max_apps_opted_in, 0);
    }

    #[test]
    fn test_v33_block_size() {
        let p = consensus_params_for_version(CONSENSUS_V33).unwrap();
        assert_eq!(p.max_txn_bytes_per_block, 5 * 1024 * 1024);
        assert_eq!(p.deeper_block_header_history, 1);
    }

    #[test]
    fn test_v34_sha256_commitment() {
        let p = consensus_params_for_version(CONSENSUS_V34).unwrap();
        assert!(p.enable_sha256_txn_commitment_header);
        assert_eq!(p.logic_sig_version, 7);
        assert_eq!(p.min_inner_appl_version, 4);
    }

    #[test]
    fn test_v36_boxes() {
        let p = consensus_params_for_version(CONSENSUS_V36).unwrap();
        assert_eq!(p.logic_sig_version, 8);
        assert_eq!(p.max_box_size, 32_768);
        assert_eq!(p.box_flat_min_balance, 2_500);
        assert_eq!(p.box_byte_min_balance, 400);
        assert_eq!(p.bytes_per_box_reference, 1_024);
    }

    #[test]
    fn test_v39_avm10() {
        let p = consensus_params_for_version(CONSENSUS_V39).unwrap();
        assert_eq!(p.logic_sig_version, 10);
        assert!(p.enable_logicsig_cost_pooling);
    }

    #[test]
    fn test_v40_avm11() {
        let p = consensus_params_for_version(CONSENSUS_V40).unwrap();
        assert_eq!(p.logic_sig_version, 11);
        assert!(p.enable_logicsig_size_pooling);
        assert!(p.enable_heartbeat);
        assert!(p.payouts_enabled);
        assert_eq!(p.payouts_max_mark_absent, 32);
        assert_eq!(p.payouts_challenge_interval, 1_000);
        assert_eq!(p.payouts_challenge_grace_period, 200);
        assert_eq!(p.payouts_challenge_bits, 5);
    }

    #[test]
    fn test_v41_avm12() {
        let p = consensus_params_for_version(CONSENSUS_V41).unwrap();
        assert_eq!(p.logic_sig_version, 12);
        assert!(p.enable_app_versioning);
        assert!(p.enable_sha512_block_hash);
        assert_eq!(p.max_app_txn_accounts, 8);
        assert_eq!(p.max_app_access, 16);
        assert_eq!(p.bytes_per_box_reference, 2_048);
    }

    // ── Protocol upgrade vote params (issue #681) ────────────────
    // go: config/consensus.go — `v41.ApprovedUpgrades[protocol.ConsensusV42] =
    // 208000` (line ~1555) is the first ConsensusCurrentVersion advance in
    // this repo's version-pin history (V41 -> V42, go-algorand v5.0.0-stable).

    #[test]
    fn test_v41_approves_v42_upgrade() {
        let v41 = consensus_params_for_version(CONSENSUS_V41).unwrap();
        assert_eq!(v41.approved_upgrade, Some((CONSENSUS_V42, 208_000)));
    }

    #[test]
    fn test_v42_has_no_further_approved_upgrade() {
        // v42 resets ApprovedUpgrades to {} — nothing beyond it is known yet.
        let v42 = consensus_params_for_version(CONSENSUS_V42).unwrap();
        assert_eq!(v42.approved_upgrade, None);
    }

    #[test]
    fn test_upgrade_vote_timing_params_inherited_to_v41_and_v42() {
        // go base struct: UpgradeVoteRounds=10000, UpgradeThreshold=9000,
        // DefaultUpgradeWaitRounds=10000 (v20+: 140000, but that's overridden
        // back down implicitly by v41/v42 inheriting straight from v20's
        // successors — assert the actual inherited chain values here).
        // MinUpgradeWaitRounds=10000/MaxUpgradeWaitRounds=150000 (v22+),
        // MaxUpgradeWaitRounds=250000 (v39+, supersedes v22's 150000).
        for version in [CONSENSUS_V41, CONSENSUS_V42] {
            let p = consensus_params_for_version(version).unwrap();
            assert_eq!(p.upgrade_vote_rounds, 10_000, "version {version}");
            assert_eq!(p.upgrade_threshold, 9_000, "version {version}");
            assert_eq!(p.default_upgrade_wait_rounds, 140_000, "version {version}");
            assert_eq!(p.min_upgrade_wait_rounds, 10_000, "version {version}");
            assert_eq!(p.max_upgrade_wait_rounds, 250_000, "version {version}");
        }
    }

    #[test]
    fn test_upgrade_wait_rounds_bounds_before_v22_are_zero() {
        // Go zero-value: MinUpgradeWaitRounds/MaxUpgradeWaitRounds are unset
        // until v22 introduces them.
        let v21 = consensus_params_for_version(CONSENSUS_V21).unwrap();
        assert_eq!(v21.min_upgrade_wait_rounds, 0);
        assert_eq!(v21.max_upgrade_wait_rounds, 0);
        let v22 = consensus_params_for_version(CONSENSUS_V22).unwrap();
        assert_eq!(v22.min_upgrade_wait_rounds, 10_000);
        assert_eq!(v22.max_upgrade_wait_rounds, 150_000);
    }

    #[test]
    fn test_default_is_v42() {
        let def = ConsensusParams::default();
        let v42 = consensus_params_for_version(CONSENSUS_V42).unwrap();
        assert_eq!(def.logic_sig_version, v42.logic_sig_version);
        assert_eq!(def.min_balance, v42.min_balance);
        assert_eq!(def.enable_heartbeat, v42.enable_heartbeat);
        assert_eq!(def.max_txn_bytes_per_block, v42.max_txn_bytes_per_block);
        assert!(def.app_size_updates);
        assert!(def.enable_pq_scheme_falcon1024);
    }

    #[test]
    fn test_consensus_v42_params() {
        // go: config/consensus.go, commit 88fe542f3 ("Consensus: Upgrade to
        // consensus version v42 (#6677)") — v42 inherits v41 and overrides
        // exactly these fields.
        let v41 = consensus_params_for_version(CONSENSUS_V41).unwrap();
        let p = consensus_params_for_version(CONSENSUS_V42).unwrap();

        assert_eq!(p.logic_sig_version, 13);
        assert_eq!(p.max_absolute_txn_note_bytes, 4_096);
        assert_eq!(p.max_absolute_extra_program_pages, 7);
        assert_eq!(p.max_absolute_total_arg_len, 16_384);
        assert_eq!(p.per_byte_txn_surcharge, 100);
        assert!(p.app_size_updates);
        assert!(p.allow_zero_local_app_ref);
        assert!(p.enforce_auth_addr_sender_diff);
        assert!(p.enable_pq_scheme_falcon1024);
        assert!(p.load_tracking);
        assert!(p.enable_select_f128);

        // Everything else is inherited unchanged from v41.
        assert_eq!(p.min_balance, v41.min_balance);
        assert_eq!(p.min_txn_fee, v41.min_txn_fee);
        assert_eq!(p.max_txn_bytes_per_block, v41.max_txn_bytes_per_block);
        assert_eq!(p.max_app_access, v41.max_app_access);
        assert_eq!(p.bytes_per_box_reference, v41.bytes_per_box_reference);
        assert_eq!(p.max_txn_note_bytes, v41.max_txn_note_bytes);
        assert_eq!(p.max_app_total_arg_len, v41.max_app_total_arg_len);
        assert_eq!(
            p.max_extra_app_program_pages,
            v41.max_extra_app_program_pages
        );

        // v41 (and earlier released versions) never had these fields set.
        assert!(!v41.app_size_updates);
        assert!(!v41.allow_zero_local_app_ref);
        assert!(!v41.enforce_auth_addr_sender_diff);
        assert!(!v41.enable_pq_scheme_falcon1024);
        assert!(!v41.load_tracking);
        assert!(!v41.enable_select_f128);
        assert_eq!(v41.max_absolute_txn_note_bytes, 0);
        // MaxAbsoluteExtraProgramPages was introduced at v28 (=3), not v42 —
        // v42 only raises it to 7. Unlike the other `max_absolute_*`/feature
        // fields above, it is NOT zero/unset pre-v42.
        assert_eq!(v41.max_absolute_extra_program_pages, 3);
        assert_eq!(v41.max_absolute_total_arg_len, 0);
        assert_eq!(v41.per_byte_txn_surcharge, 0);
    }

    #[test]
    fn test_consensus_v42_spec_url() {
        assert_eq!(
            CONSENSUS_V42,
            "https://github.com/algorandfoundation/specs/tree/268b63433a907455d439995bf916f6b296018f4f"
        );
    }

    #[test]
    fn test_future_version() {
        // go: vFuture := v42 (commit 88fe542f3) — future now inherits v42's
        // fields (previously only enforce_auth_addr_sender_diff/load_tracking
        // were future-only overrides bolted onto v41) and bumps
        // LogicSigVersion once more for the next in-development AVM version.
        let p = consensus_params_for_version(CONSENSUS_FUTURE).unwrap();
        let v42 = consensus_params_for_version(CONSENSUS_V42).unwrap();
        assert_eq!(p.logic_sig_version, 14);
        assert!(p.enforce_auth_addr_sender_diff);
        assert!(p.load_tracking);
        assert!(p.app_size_updates);
        assert!(p.allow_zero_local_app_ref);
        assert!(p.enable_pq_scheme_falcon1024);
        assert!(p.enable_select_f128);
        assert_eq!(
            p.max_absolute_txn_note_bytes,
            v42.max_absolute_txn_note_bytes
        );
        assert_eq!(p.per_byte_txn_surcharge, v42.per_byte_txn_surcharge);
    }

    #[test]
    fn test_load_tracking_not_on_pre_v42_versions() {
        // LoadTracking was future-only per go-algorand config/consensus.go
        // (v4.7.0-beta, PR #6548) until commit 88fe542f3 moved it onto the
        // real v42 release — must stay off on every version before v42.
        for v in [CONSENSUS_V38, CONSENSUS_V39, CONSENSUS_V40, CONSENSUS_V41] {
            let p = consensus_params_for_version(v).unwrap();
            assert!(!p.load_tracking, "{v} must not have load_tracking set");
        }
        let v42 = consensus_params_for_version(CONSENSUS_V42).unwrap();
        assert!(v42.load_tracking, "v42 must have load_tracking set");
    }

    #[test]
    fn test_unknown_version_returns_none() {
        assert!(consensus_params_for_version("v99").is_none());
        assert!(consensus_params_for_version("").is_none());
    }

    #[test]
    fn test_all_known_versions_resolve() {
        for &ver in KNOWN_PROTOCOL_VERSIONS {
            assert!(
                consensus_params_for_version(ver).is_some(),
                "version {ver} should resolve"
            );
        }
    }

    #[test]
    fn test_alpha_versions() {
        let a1 = consensus_params_for_version(CONSENSUS_ALPHA1).unwrap();
        assert_eq!(a1.max_txn_bytes_per_block, 5_000_000);

        let a2 = consensus_params_for_version(CONSENSUS_ALPHA2).unwrap();
        assert_eq!(a2.max_txn_bytes_per_block, 5 * 1024 * 1024);

        let a3 = consensus_params_for_version(CONSENSUS_ALPHA3).unwrap();
        let v33 = consensus_params_for_version(CONSENSUS_V33).unwrap();
        assert_eq!(
            a3.deeper_block_header_history,
            v33.deeper_block_header_history
        );

        let a4 = consensus_params_for_version(CONSENSUS_ALPHA4).unwrap();
        let v34 = consensus_params_for_version(CONSENSUS_V34).unwrap();
        assert_eq!(a4.logic_sig_version, v34.logic_sig_version);

        let a5 = consensus_params_for_version(CONSENSUS_ALPHA5).unwrap();
        let v36 = consensus_params_for_version(CONSENSUS_V36).unwrap();
        assert_eq!(a5.logic_sig_version, v36.logic_sig_version);
    }

    #[test]
    fn test_fnet_versions() {
        // go: config/consensus.go (v5.0.0-stable) vFnet1: v39 base with
        // LogicSigVersion=11 and FNet-tuned payouts/bonus.
        let f1 = consensus_params_for_version(CONSENSUS_VFNET1).unwrap();
        let v39 = consensus_params_for_version(CONSENSUS_V39).unwrap();
        assert_eq!(f1.logic_sig_version, 11);
        assert!(f1.payouts_enabled);
        assert_eq!(f1.payouts_percent, 75);
        assert_eq!(f1.payouts_go_online_fee, 2_000_000);
        assert_eq!(f1.payouts_min_balance, 30_000_000_000);
        assert_eq!(f1.payouts_max_balance, 70_000_000_000_000);
        assert_eq!(f1.payouts_max_mark_absent, 32);
        assert_eq!(f1.payouts_challenge_interval, 1_000);
        assert_eq!(f1.payouts_challenge_grace_period, 200);
        assert_eq!(f1.payouts_challenge_bits, 5);
        assert_eq!(f1.bonus_base_amount, 10_000_000);
        assert_eq!(f1.bonus_decay_interval, 250_000);
        // Everything else carried unchanged from v39.
        assert_eq!(
            f1.enable_logicsig_cost_pooling,
            v39.enable_logicsig_cost_pooling
        );

        // fnet2: no parameter change from fnet1.
        let f2 = consensus_params_for_version(CONSENSUS_VFNET2).unwrap();
        assert_eq!(f2.logic_sig_version, f1.logic_sig_version);
        assert_eq!(f2.payouts_challenge_interval, f1.payouts_challenge_interval);

        // fnet3: challenges disabled (no heartbeats yet), otherwise same as fnet2.
        let f3 = consensus_params_for_version(CONSENSUS_VFNET3).unwrap();
        assert_eq!(f3.payouts_challenge_interval, 0);
        assert_eq!(f3.payouts_percent, f1.payouts_percent);

        // fnet4: back to fnet1's parameters (challenges re-enabled).
        let f4 = consensus_params_for_version(CONSENSUS_VFNET4).unwrap();
        assert_eq!(f4.payouts_challenge_interval, f1.payouts_challenge_interval);
        assert_eq!(f4.logic_sig_version, f1.logic_sig_version);

        // FNet entries must never be reachable through mainnet/testnet's own
        // version strings — they are additive, standalone table entries.
        assert_ne!(CONSENSUS_VFNET1, CONSENSUS_V39);
        assert_ne!(CONSENSUS_VFNET1, CONSENSUS_CURRENT_VERSION);
    }

    #[test]
    fn test_challenge_params_absent_before_v40() {
        // Before v31, max_proposed_expired_online_accounts should be 0
        let v30 = consensus_params_for_version(CONSENSUS_V30).unwrap();
        assert_eq!(v30.max_proposed_expired_online_accounts, 0);

        // Before v40, challenge params should be 0
        let v39 = consensus_params_for_version(CONSENSUS_V39).unwrap();
        assert_eq!(v39.payouts_max_mark_absent, 0);
        assert_eq!(v39.payouts_challenge_interval, 0);
        assert_eq!(v39.payouts_challenge_grace_period, 0);
        assert_eq!(v39.payouts_challenge_bits, 0);
        assert!(!v39.payouts_enabled);

        // v31 introduces max_proposed_expired_online_accounts but not challenge params
        let v31 = consensus_params_for_version(CONSENSUS_V31).unwrap();
        assert_eq!(v31.max_proposed_expired_online_accounts, 32);
        assert_eq!(v31.payouts_challenge_interval, 0);
    }

    #[test]
    fn test_challenge_params_inherited_v41() {
        // v41 inherits challenge params from v40
        let v41 = consensus_params_for_version(CONSENSUS_V41).unwrap();
        assert_eq!(v41.payouts_max_mark_absent, 32);
        assert_eq!(v41.payouts_challenge_interval, 1_000);
        assert_eq!(v41.payouts_challenge_grace_period, 200);
        assert_eq!(v41.payouts_challenge_bits, 5);
        assert_eq!(v41.max_proposed_expired_online_accounts, 32);
    }

    #[test]
    fn test_version_inheritance_chain() {
        // Verify that key features accumulate through the version chain
        let v23 = consensus_params_for_version(CONSENSUS_V23).unwrap();
        assert!(v23.fix_transaction_leases);
        assert!(!v23.support_rekeying);

        let v24 = consensus_params_for_version(CONSENSUS_V24).unwrap();
        assert!(v24.fix_transaction_leases); // inherited from v23
        assert!(v24.support_rekeying); // new in v24

        let v28 = consensus_params_for_version(CONSENSUS_V28).unwrap();
        assert!(v28.fix_transaction_leases); // inherited
        assert!(v28.support_rekeying); // inherited
        assert!(v28.enable_fee_pooling); // new in v28
    }

    // ── Agreement / committee parameter regression tests ────────────
    // Verify that agreement-related fields match go-algorand config/consensus.go
    // at tag v4.6.0-stable for every version where they change.

    #[test]
    fn test_agreement_params_v7() {
        let p = consensus_params_for_version(CONSENSUS_V7).unwrap();
        // Committee sizes & thresholds
        assert_eq!(p.num_proposers, 30);
        assert_eq!(p.soft_committee_size, 2500);
        assert_eq!(p.soft_committee_threshold, 1870);
        assert_eq!(p.cert_committee_size, 1000);
        assert_eq!(p.cert_committee_threshold, 720);
        assert_eq!(p.next_committee_size, 10000);
        assert_eq!(p.next_committee_threshold, 7750);
        assert_eq!(p.late_committee_size, 10000);
        assert_eq!(p.late_committee_threshold, 7750);
        assert_eq!(p.redo_committee_size, 10000);
        assert_eq!(p.redo_committee_threshold, 7750);
        assert_eq!(p.down_committee_size, 10000);
        assert_eq!(p.down_committee_threshold, 7750);
        // Timeouts
        assert_eq!(p.agreement_filter_timeout, Duration::from_secs(4));
        assert_eq!(p.agreement_filter_timeout_period0, Duration::from_secs(4));
        // BigLambda (15s) + SmallLambda (2s) = 17s
        assert_eq!(
            p.agreement_deadline_timeout_period0,
            Duration::from_millis(17000)
        );
        assert_eq!(p.fast_recovery_lambda, Duration::from_secs(300));
        // Seed / sortition
        assert_eq!(p.seed_lookback, 2);
        assert_eq!(p.seed_refresh_interval, 100);
        assert_eq!(p.max_bal_lookback, 320);
        // Key management
        assert_eq!(p.default_key_dilution, 10000);
        assert!(!p.credential_domain_separation_enabled);
        // Dynamic filter
        assert!(!p.dynamic_filter_timeout);
    }

    #[test]
    fn test_agreement_params_v8() {
        let p = consensus_params_for_version(CONSENSUS_V8).unwrap();
        // v8: new analysis parameters from Georgios
        assert_eq!(p.seed_refresh_interval, 80);
        assert_eq!(p.num_proposers, 9);
        assert_eq!(p.soft_committee_size, 2990);
        assert_eq!(p.soft_committee_threshold, 2267);
        assert_eq!(p.cert_committee_size, 1500);
        assert_eq!(p.cert_committee_threshold, 1112);
        assert_eq!(p.next_committee_size, 5000);
        assert_eq!(p.next_committee_threshold, 3838);
        assert_eq!(p.late_committee_size, 5000);
        assert_eq!(p.late_committee_threshold, 3838);
        assert_eq!(p.redo_committee_size, 5000);
        assert_eq!(p.redo_committee_threshold, 3838);
        assert_eq!(p.down_committee_size, 5000);
        assert_eq!(p.down_committee_threshold, 3838);
        // Unchanged from v7
        assert_eq!(p.agreement_filter_timeout, Duration::from_secs(4));
        assert_eq!(p.agreement_filter_timeout_period0, Duration::from_secs(4));
        assert_eq!(
            p.agreement_deadline_timeout_period0,
            Duration::from_millis(17000)
        );
        assert_eq!(p.fast_recovery_lambda, Duration::from_secs(300));
        assert_eq!(p.seed_lookback, 2);
        assert_eq!(p.max_bal_lookback, 320);
        assert_eq!(p.default_key_dilution, 10000);
        assert!(!p.credential_domain_separation_enabled);
        assert!(!p.dynamic_filter_timeout);
    }

    #[test]
    fn test_agreement_params_v10() {
        let p = consensus_params_for_version(CONSENSUS_V10).unwrap();
        // v10: fast partition recovery + raised NumProposers
        assert_eq!(p.num_proposers, 20);
        assert_eq!(p.late_committee_size, 500);
        assert_eq!(p.late_committee_threshold, 320);
        assert_eq!(p.redo_committee_size, 2400);
        assert_eq!(p.redo_committee_threshold, 1768);
        assert_eq!(p.down_committee_size, 6000);
        assert_eq!(p.down_committee_threshold, 4560);
        // Inherited from v8 (unchanged)
        assert_eq!(p.soft_committee_size, 2990);
        assert_eq!(p.soft_committee_threshold, 2267);
        assert_eq!(p.cert_committee_size, 1500);
        assert_eq!(p.cert_committee_threshold, 1112);
        assert_eq!(p.next_committee_size, 5000);
        assert_eq!(p.next_committee_threshold, 3838);
        assert_eq!(p.seed_refresh_interval, 80);
    }

    #[test]
    fn test_agreement_params_v16() {
        let p = consensus_params_for_version(CONSENSUS_V16).unwrap();
        // v16: credential domain separation enabled
        assert!(p.credential_domain_separation_enabled);
        // Committee params inherited from v10 (through v11-v15)
        assert_eq!(p.num_proposers, 20);
        assert_eq!(p.soft_committee_size, 2990);
        assert_eq!(p.cert_committee_size, 1500);
        assert_eq!(p.late_committee_size, 500);
        assert_eq!(p.redo_committee_size, 2400);
        assert_eq!(p.down_committee_size, 6000);
    }

    #[test]
    fn test_agreement_params_v34() {
        let p = consensus_params_for_version(CONSENSUS_V34).unwrap();
        // v34: filter timeout period0 changed to 3400ms
        assert_eq!(
            p.agreement_filter_timeout_period0,
            Duration::from_millis(3400)
        );
        // Other timeouts unchanged
        assert_eq!(p.agreement_filter_timeout, Duration::from_secs(4));
        assert_eq!(
            p.agreement_deadline_timeout_period0,
            Duration::from_millis(17000)
        );
        assert_eq!(p.fast_recovery_lambda, Duration::from_secs(300));
        assert!(!p.dynamic_filter_timeout);
    }

    #[test]
    fn test_agreement_params_v38() {
        let p = consensus_params_for_version(CONSENSUS_V38).unwrap();
        // v38: filter timeout period0 changed to 3000ms
        assert_eq!(
            p.agreement_filter_timeout_period0,
            Duration::from_millis(3000)
        );
        // Other timeouts still unchanged
        assert_eq!(p.agreement_filter_timeout, Duration::from_secs(4));
        assert_eq!(
            p.agreement_deadline_timeout_period0,
            Duration::from_millis(17000)
        );
        assert!(!p.dynamic_filter_timeout);
    }

    #[test]
    fn test_agreement_params_v39() {
        let p = consensus_params_for_version(CONSENSUS_V39).unwrap();
        // v39: deadline timeout changed, dynamic filter enabled
        assert_eq!(p.agreement_deadline_timeout_period0, Duration::from_secs(4));
        assert!(p.dynamic_filter_timeout);
        // Filter timeout period0 inherited from v38
        assert_eq!(
            p.agreement_filter_timeout_period0,
            Duration::from_millis(3000)
        );
        assert_eq!(p.agreement_filter_timeout, Duration::from_secs(4));
        assert_eq!(p.fast_recovery_lambda, Duration::from_secs(300));
    }

    #[test]
    fn test_agreement_params_v41_inherited() {
        // v41 inherits all agreement params from v39 (through v40)
        let p = consensus_params_for_version(CONSENSUS_V41).unwrap();
        assert_eq!(p.num_proposers, 20);
        assert_eq!(p.soft_committee_size, 2990);
        assert_eq!(p.soft_committee_threshold, 2267);
        assert_eq!(p.cert_committee_size, 1500);
        assert_eq!(p.cert_committee_threshold, 1112);
        assert_eq!(p.next_committee_size, 5000);
        assert_eq!(p.next_committee_threshold, 3838);
        assert_eq!(p.late_committee_size, 500);
        assert_eq!(p.late_committee_threshold, 320);
        assert_eq!(p.redo_committee_size, 2400);
        assert_eq!(p.redo_committee_threshold, 1768);
        assert_eq!(p.down_committee_size, 6000);
        assert_eq!(p.down_committee_threshold, 4560);
        assert_eq!(p.agreement_filter_timeout, Duration::from_secs(4));
        assert_eq!(
            p.agreement_filter_timeout_period0,
            Duration::from_millis(3000)
        );
        assert_eq!(p.agreement_deadline_timeout_period0, Duration::from_secs(4));
        assert_eq!(p.fast_recovery_lambda, Duration::from_secs(300));
        assert_eq!(p.seed_lookback, 2);
        assert_eq!(p.seed_refresh_interval, 80);
        assert_eq!(p.max_bal_lookback, 320);
        assert_eq!(p.default_key_dilution, 10000);
        assert!(p.credential_domain_separation_enabled);
        assert!(p.dynamic_filter_timeout);
    }

    #[test]
    fn test_agreement_params_future_inherited() {
        // future inherits all agreement params from v41
        let p = consensus_params_for_version(CONSENSUS_FUTURE).unwrap();
        let v41 = consensus_params_for_version(CONSENSUS_V41).unwrap();
        assert_eq!(p.num_proposers, v41.num_proposers);
        assert_eq!(p.soft_committee_size, v41.soft_committee_size);
        assert_eq!(p.soft_committee_threshold, v41.soft_committee_threshold);
        assert_eq!(p.cert_committee_size, v41.cert_committee_size);
        assert_eq!(p.cert_committee_threshold, v41.cert_committee_threshold);
        assert_eq!(p.next_committee_size, v41.next_committee_size);
        assert_eq!(p.next_committee_threshold, v41.next_committee_threshold);
        assert_eq!(p.late_committee_size, v41.late_committee_size);
        assert_eq!(p.late_committee_threshold, v41.late_committee_threshold);
        assert_eq!(p.redo_committee_size, v41.redo_committee_size);
        assert_eq!(p.redo_committee_threshold, v41.redo_committee_threshold);
        assert_eq!(p.down_committee_size, v41.down_committee_size);
        assert_eq!(p.down_committee_threshold, v41.down_committee_threshold);
        assert_eq!(p.agreement_filter_timeout, v41.agreement_filter_timeout);
        assert_eq!(
            p.agreement_filter_timeout_period0,
            v41.agreement_filter_timeout_period0
        );
        assert_eq!(
            p.agreement_deadline_timeout_period0,
            v41.agreement_deadline_timeout_period0
        );
        assert_eq!(p.fast_recovery_lambda, v41.fast_recovery_lambda);
        assert_eq!(p.seed_lookback, v41.seed_lookback);
        assert_eq!(p.seed_refresh_interval, v41.seed_refresh_interval);
        assert_eq!(p.max_bal_lookback, v41.max_bal_lookback);
        assert_eq!(p.default_key_dilution, v41.default_key_dilution);
        assert_eq!(
            p.credential_domain_separation_enabled,
            v41.credential_domain_separation_enabled
        );
        assert_eq!(p.dynamic_filter_timeout, v41.dynamic_filter_timeout);
    }

    #[test]
    fn test_agreement_params_alpha1() {
        let p = consensus_params_for_version(CONSENSUS_ALPHA1).unwrap();
        // alpha1 inherits from v32, which inherits committee params from v10
        assert_eq!(p.num_proposers, 20);
        assert_eq!(p.soft_committee_size, 2990);
        assert_eq!(p.cert_committee_size, 1500);
        // alpha1 overrides AgreementFilterTimeoutPeriod0 to 2s
        assert_eq!(p.agreement_filter_timeout_period0, Duration::from_secs(2));
        // Other timeouts inherited from v32 (= v7 base values)
        assert_eq!(p.agreement_filter_timeout, Duration::from_secs(4));
        assert_eq!(
            p.agreement_deadline_timeout_period0,
            Duration::from_millis(17000)
        );
        assert!(!p.dynamic_filter_timeout);
    }

    #[test]
    fn test_agreement_params_alpha2() {
        let p = consensus_params_for_version(CONSENSUS_ALPHA2).unwrap();
        // alpha2 inherits from alpha1 but overrides filter timeout period0
        assert_eq!(
            p.agreement_filter_timeout_period0,
            Duration::from_millis(3500)
        );
        assert_eq!(p.agreement_filter_timeout, Duration::from_secs(4));
    }

    #[test]
    fn test_agreement_params_no_change_v9_through_v15() {
        // v9 through v15: committee params should be same as v8/v10
        // (v9 inherits v8 committee, v10 overrides some, v11-v15 inherit v10)
        let v9 = consensus_params_for_version(CONSENSUS_V9).unwrap();
        let v8 = consensus_params_for_version(CONSENSUS_V8).unwrap();
        assert_eq!(v9.num_proposers, v8.num_proposers);
        assert_eq!(v9.soft_committee_size, v8.soft_committee_size);
        assert_eq!(v9.cert_committee_size, v8.cert_committee_size);
        assert_eq!(v9.late_committee_size, v8.late_committee_size);

        // v11-v15 inherit from v10
        for &ver in &[
            CONSENSUS_V11,
            CONSENSUS_V12,
            CONSENSUS_V13,
            CONSENSUS_V14,
            CONSENSUS_V15,
        ] {
            let p = consensus_params_for_version(ver).unwrap();
            assert_eq!(p.num_proposers, 20, "v{ver} num_proposers");
            assert_eq!(p.late_committee_size, 500, "v{ver} late_committee_size");
            assert_eq!(p.redo_committee_size, 2400, "v{ver} redo_committee_size");
            assert_eq!(p.down_committee_size, 6000, "v{ver} down_committee_size");
            assert!(!p.credential_domain_separation_enabled);
        }
    }

    #[test]
    fn test_agreement_timeouts_stable_v16_to_v33() {
        // From v16 to v33, agreement timeouts should remain unchanged from v7 base
        for &ver in &[
            CONSENSUS_V16,
            CONSENSUS_V17,
            CONSENSUS_V18,
            CONSENSUS_V24,
            CONSENSUS_V28,
            CONSENSUS_V30,
            CONSENSUS_V31,
            CONSENSUS_V32,
            CONSENSUS_V33,
        ] {
            let p = consensus_params_for_version(ver).unwrap();
            assert_eq!(
                p.agreement_filter_timeout,
                Duration::from_secs(4),
                "{ver} filter_timeout"
            );
            assert_eq!(
                p.agreement_filter_timeout_period0,
                Duration::from_secs(4),
                "{ver} filter_timeout_period0"
            );
            assert_eq!(
                p.agreement_deadline_timeout_period0,
                Duration::from_millis(17000),
                "{ver} deadline_timeout_period0"
            );
            assert_eq!(
                p.fast_recovery_lambda,
                Duration::from_secs(300),
                "{ver} fast_recovery_lambda"
            );
            assert!(!p.dynamic_filter_timeout, "{ver} dynamic_filter_timeout");
        }
    }

    #[test]
    fn test_credential_domain_separation_versions() {
        // Not enabled before v16
        for &ver in &[
            CONSENSUS_V7,
            CONSENSUS_V8,
            CONSENSUS_V9,
            CONSENSUS_V10,
            CONSENSUS_V11,
            CONSENSUS_V12,
            CONSENSUS_V13,
            CONSENSUS_V14,
            CONSENSUS_V15,
        ] {
            let p = consensus_params_for_version(ver).unwrap();
            assert!(
                !p.credential_domain_separation_enabled,
                "{ver} should not have credential domain separation"
            );
        }
        // Enabled from v16 onward
        for &ver in &[
            CONSENSUS_V16,
            CONSENSUS_V17,
            CONSENSUS_V18,
            CONSENSUS_V24,
            CONSENSUS_V28,
            CONSENSUS_V34,
            CONSENSUS_V38,
            CONSENSUS_V39,
            CONSENSUS_V40,
            CONSENSUS_V41,
        ] {
            let p = consensus_params_for_version(ver).unwrap();
            assert!(
                p.credential_domain_separation_enabled,
                "{ver} should have credential domain separation"
            );
        }
    }

    // ── issue #747: historical-replay-correctness fields ────────────────

    #[test]
    fn test_pending_residue_rewards_v18_activation() {
        assert!(
            !consensus_params_for_version(CONSENSUS_V17)
                .unwrap()
                .pending_residue_rewards
        );
        assert!(
            consensus_params_for_version(CONSENSUS_V18)
                .unwrap()
                .pending_residue_rewards
        );
        assert!(
            consensus_params_for_version(CONSENSUS_V41)
                .unwrap()
                .pending_residue_rewards
        );
    }

    #[test]
    fn test_initial_rewards_rate_calculation_v26_activation() {
        assert!(
            !consensus_params_for_version(CONSENSUS_V25)
                .unwrap()
                .initial_rewards_rate_calculation
        );
        assert!(
            consensus_params_for_version(CONSENSUS_V26)
                .unwrap()
                .initial_rewards_rate_calculation
        );
        assert!(
            consensus_params_for_version(CONSENSUS_V41)
                .unwrap()
                .initial_rewards_rate_calculation
        );
    }

    #[test]
    fn test_rewards_calculation_fix_v31_activation() {
        assert!(
            !consensus_params_for_version(CONSENSUS_V30)
                .unwrap()
                .rewards_calculation_fix
        );
        assert!(
            consensus_params_for_version(CONSENSUS_V31)
                .unwrap()
                .rewards_calculation_fix
        );
        assert!(
            consensus_params_for_version(CONSENSUS_V41)
                .unwrap()
                .rewards_calculation_fix
        );
    }

    #[test]
    fn test_v34_activation_cluster() {
        // UnifyInnerTxIDs, UnfundedSenders, StateProofTopVoters all activate
        // together at v34 (config/consensus.go:1379,1388,1392).
        let v33 = consensus_params_for_version(CONSENSUS_V33).unwrap();
        assert!(!v33.unify_inner_tx_ids);
        assert!(!v33.unfunded_senders);
        assert_eq!(v33.state_proof_top_voters, 0);

        let v34 = consensus_params_for_version(CONSENSUS_V34).unwrap();
        assert!(v34.unify_inner_tx_ids);
        assert!(v34.unfunded_senders);
        assert_eq!(v34.state_proof_top_voters, 1024);

        let v41 = consensus_params_for_version(CONSENSUS_V41).unwrap();
        assert!(v41.unify_inner_tx_ids);
        assert!(v41.unfunded_senders);
        assert_eq!(v41.state_proof_top_voters, 1024);
    }

    #[test]
    fn test_v38_activation_cluster() {
        // EnablePrecheckECDSACurve, AppForbidLowResources both activate
        // together at v38 (config/consensus.go:1446-1447).
        let v37 = consensus_params_for_version(CONSENSUS_V37).unwrap();
        assert!(!v37.enable_precheck_ecdsa_curve);
        assert!(!v37.app_forbid_low_resources);

        let v38 = consensus_params_for_version(CONSENSUS_V38).unwrap();
        assert!(v38.enable_precheck_ecdsa_curve);
        assert!(v38.app_forbid_low_resources);

        let v41 = consensus_params_for_version(CONSENSUS_V41).unwrap();
        assert!(v41.enable_precheck_ecdsa_curve);
        assert!(v41.app_forbid_low_resources);
    }

    // ── Issue #752: LogicSigMsig/LMsig, EnableBareBudgetError,
    // StateProofMaxRecoveryIntervals, CatchpointLookback,
    // EnableLedgerDataUpdateRound, StateProofUseTrackerVerification,
    // EnableCatchpointsWithSPContexts/EnableCatchpointsWithOnlineAccounts ──

    #[test]
    fn logic_sig_msig_and_lmsig_swap_at_v41() {
        // v18 introduces LogicSigMsig=true, retroactively formalized by
        // commit `3b1ac0f59` (config/consensus.go:1066).
        let v17 = consensus_params_for_version(CONSENSUS_V17).unwrap();
        assert!(!v17.logic_sig_msig);
        assert!(!v17.logic_sig_lmsig);

        let v18 = consensus_params_for_version(CONSENSUS_V18).unwrap();
        assert!(v18.logic_sig_msig);
        assert!(!v18.logic_sig_lmsig);

        let v40 = consensus_params_for_version(CONSENSUS_V40).unwrap();
        assert!(v40.logic_sig_msig);
        assert!(!v40.logic_sig_lmsig);

        // v41 retires LogicSigMsig in favor of LogicSigLMsig, in the same
        // release (config/consensus.go:1525-1526).
        let v41 = consensus_params_for_version(CONSENSUS_V41).unwrap();
        assert!(!v41.logic_sig_msig);
        assert!(v41.logic_sig_lmsig);

        let v42 = consensus_params_for_version(CONSENSUS_V42).unwrap();
        assert!(!v42.logic_sig_msig);
        assert!(v42.logic_sig_lmsig);
    }

    #[test]
    fn enable_bare_budget_error_activates_at_v38() {
        let v37 = consensus_params_for_version(CONSENSUS_V37).unwrap();
        assert!(!v37.enable_bare_budget_error);
        let v38 = consensus_params_for_version(CONSENSUS_V38).unwrap();
        assert!(v38.enable_bare_budget_error);
        let v42 = consensus_params_for_version(CONSENSUS_V42).unwrap();
        assert!(v42.enable_bare_budget_error);
    }

    #[test]
    fn state_proof_max_recovery_intervals_activates_at_v34() {
        let v33 = consensus_params_for_version(CONSENSUS_V33).unwrap();
        assert_eq!(v33.state_proof_max_recovery_intervals, 0);
        let v34 = consensus_params_for_version(CONSENSUS_V34).unwrap();
        assert_eq!(v34.state_proof_max_recovery_intervals, 10);
        let v42 = consensus_params_for_version(CONSENSUS_V42).unwrap();
        assert_eq!(v42.state_proof_max_recovery_intervals, 10);
    }

    #[test]
    fn catchpoint_lookback_activates_at_v33_distinct_from_max_bal_lookback() {
        let v32 = consensus_params_for_version(CONSENSUS_V32).unwrap();
        assert_eq!(v32.catchpoint_lookback, 0);
        // `max_bal_lookback` (a different field) is 320 from the v7 base,
        // unconditionally -- must not be confused with `catchpoint_lookback`.
        assert_eq!(v32.max_bal_lookback, 320);

        let v33 = consensus_params_for_version(CONSENSUS_V33).unwrap();
        assert_eq!(v33.catchpoint_lookback, 320);
        assert_eq!(v33.max_bal_lookback, 320);

        let v42 = consensus_params_for_version(CONSENSUS_V42).unwrap();
        assert_eq!(v42.catchpoint_lookback, 320);
    }

    #[test]
    fn enable_ledger_data_update_round_activates_at_v32() {
        let v31 = consensus_params_for_version(CONSENSUS_V31).unwrap();
        assert!(!v31.enable_ledger_data_update_round);
        let v32 = consensus_params_for_version(CONSENSUS_V32).unwrap();
        assert!(v32.enable_ledger_data_update_round);
        let v42 = consensus_params_for_version(CONSENSUS_V42).unwrap();
        assert!(v42.enable_ledger_data_update_round);
    }

    #[test]
    fn state_proof_use_tracker_verification_and_sp_contexts_activate_at_v38() {
        let v37 = consensus_params_for_version(CONSENSUS_V37).unwrap();
        assert!(!v37.state_proof_use_tracker_verification);
        assert!(!v37.enable_catchpoints_with_sp_contexts);

        let v38 = consensus_params_for_version(CONSENSUS_V38).unwrap();
        assert!(v38.state_proof_use_tracker_verification);
        assert!(v38.enable_catchpoints_with_sp_contexts);

        let v42 = consensus_params_for_version(CONSENSUS_V42).unwrap();
        assert!(v42.state_proof_use_tracker_verification);
        assert!(v42.enable_catchpoints_with_sp_contexts);
    }

    #[test]
    fn enable_catchpoints_with_online_accounts_activates_at_v40() {
        let v39 = consensus_params_for_version(CONSENSUS_V39).unwrap();
        assert!(!v39.enable_catchpoints_with_online_accounts);
        // SP contexts must already be on by v39 (activated at v38), so v40's
        // online-accounts flag is a valid V8-selecting combination.
        assert!(v39.enable_catchpoints_with_sp_contexts);

        let v40 = consensus_params_for_version(CONSENSUS_V40).unwrap();
        assert!(v40.enable_catchpoints_with_online_accounts);
        assert!(v40.enable_catchpoints_with_sp_contexts);

        let v42 = consensus_params_for_version(CONSENSUS_V42).unwrap();
        assert!(v42.enable_catchpoints_with_online_accounts);
    }

    #[test]
    fn consensus_json_override_round_trips_issue_752_fields() {
        // A `consensus.json` override that sets one of the new fields must
        // survive the JSON round trip and merge correctly (issue #762's
        // override registry, extended by issue #752's new fields).
        let json = r#"{
            "vTest752": {
                "LogicSigMsig": false,
                "LogicSigLMsig": true,
                "EnableBareBudgetError": true,
                "StateProofMaxRecoveryIntervals": 7,
                "StateProofUseTrackerVerification": true,
                "CatchpointLookback": 640,
                "EnableLedgerDataUpdateRound": true,
                "EnableCatchpointsWithSPContexts": true,
                "EnableCatchpointsWithOnlineAccounts": true
            }
        }"#;
        let overrides: ConsensusOverrides = serde_json::from_str(json).unwrap();
        let entry = overrides.get("vTest752").expect("entry must parse");
        assert!(!entry.logic_sig_msig);
        assert!(entry.logic_sig_lmsig);
        assert!(entry.enable_bare_budget_error);
        assert_eq!(entry.state_proof_max_recovery_intervals, 7);
        assert!(entry.state_proof_use_tracker_verification);
        assert_eq!(entry.catchpoint_lookback, 640);
        assert!(entry.enable_ledger_data_update_round);
        assert!(entry.enable_catchpoints_with_sp_contexts);
        assert!(entry.enable_catchpoints_with_online_accounts);

        let params = entry.to_consensus_params();
        assert!(!params.logic_sig_msig);
        assert!(params.logic_sig_lmsig);
        assert!(params.enable_bare_budget_error);
        assert_eq!(params.state_proof_max_recovery_intervals, 7);
        assert!(params.state_proof_use_tracker_verification);
        assert_eq!(params.catchpoint_lookback, 640);
        assert!(params.enable_ledger_data_update_round);
        assert!(params.enable_catchpoints_with_sp_contexts);
        assert!(params.enable_catchpoints_with_online_accounts);
    }
}
