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

//! `goal protocols` (`cmd/goal/commands.go` `protoCmd`), issue #2467:
//! `os.Stdout.Write(protocol.EncodeJSON(config.Consensus))`, go-codec's JSON
//! of the built-in `config.ConsensusProtocols` map (goal never loads a
//! `consensus.json` into `config.Consensus`; only `algod` does).
//!
//! go-codec (`protocol.JSONHandle`: `Canonical`, `Indent: 2`) writes the map
//! with its keys sorted and each `config.ConsensusParams` with every field
//! (none is `omitempty`), sorted by name; a `time.Duration` is its
//! nanoseconds, `ApprovedUpgrades` a map, `Bonus` / `Payouts` structs.

use algo_types::consensus::{self as c, ConsensusParams};

use crate::transcode::{encode_protocol_json, Json};

/// The protocols whose `ApplyData` is false: `config/consensus.go` sets it
/// on `v14` and every later version derives from that one.
const BEFORE_APPLY_DATA: [&str; 7] = [
    c::CONSENSUS_V7,
    c::CONSENSUS_V8,
    c::CONSENSUS_V9,
    c::CONSENSUS_V10,
    c::CONSENSUS_V11,
    c::CONSENSUS_V12,
    c::CONSENSUS_V13,
];

/// The protocols whose `TxnCounter` is false: go sets it on `v18`.
const BEFORE_TXN_COUNTER: [&str; 4] = [
    c::CONSENSUS_V14,
    c::CONSENSUS_V15,
    c::CONSENSUS_V16,
    c::CONSENSUS_V17,
];

/// The `ApprovedUpgrades` of the test-network protocols
/// (`config/consensus.go`: `vAlphaN.ApprovedUpgrades[vAlphaN+1]`,
/// `vFnetN.ApprovedUpgrades[...]`), which
/// [`c::HISTORICAL_APPROVED_UPGRADES`] leaves out.
const TEST_NETWORK_UPGRADES: [(&str, &str, u64); 7] = [
    (c::CONSENSUS_ALPHA1, c::CONSENSUS_ALPHA2, 10_000),
    (c::CONSENSUS_ALPHA2, c::CONSENSUS_ALPHA3, 10_000),
    (c::CONSENSUS_ALPHA3, c::CONSENSUS_ALPHA4, 10_000),
    (c::CONSENSUS_ALPHA4, c::CONSENSUS_ALPHA5, 10_000),
    (c::CONSENSUS_VFNET1, c::CONSENSUS_VFNET2, 10_000),
    (c::CONSENSUS_VFNET2, c::CONSENSUS_VFNET3, 10_000),
    (c::CONSENSUS_VFNET3, c::CONSENSUS_VFNET4, 10_000),
];

/// `vFnet4.ApprovedUpgrades[protocol.ConsensusV40] = 10000`.
const FNET4_UPGRADE: (&str, &str, u64) = (c::CONSENSUS_VFNET4, c::CONSENSUS_V40, 10_000);

fn key(s: &str) -> Json {
    Json::Str(s.as_bytes().to_vec())
}

fn dur(d: std::time::Duration) -> Json {
    // a `time.Duration` is an int64 of nanoseconds
    Json::Uint(d.as_nanos() as u64)
}

/// A struct: its fields sorted by name, as go-codec's `Canonical` writes them.
fn object(mut fields: Vec<(&str, Json)>) -> Json {
    fields.sort_by(|a, b| a.0.cmp(b.0));
    Json::Ordered(fields.into_iter().map(|(k, v)| (key(k), v)).collect())
}

/// go's `ApprovedUpgrades` of `version`.
fn approved_upgrades(version: &str) -> Json {
    let mut ups: Vec<(&str, u64)> = c::HISTORICAL_APPROVED_UPGRADES
        .iter()
        .chain(TEST_NETWORK_UPGRADES.iter())
        .chain(std::iter::once(&FNET4_UPGRADE))
        .filter(|(from, _, _)| *from == version)
        .map(|(_, to, delay)| (*to, *delay))
        .collect();
    ups.sort_by(|a, b| a.0.cmp(b.0));
    Json::Ordered(
        ups.into_iter()
            .map(|(k, v)| (key(k), Json::Uint(v)))
            .collect(),
    )
}

/// go-codec's JSON shape of one `config.ConsensusParams`.
fn params_json(version: &str, p: &ConsensusParams) -> Json {
    let f: Vec<(&str, Json)> = vec![
        (
            "AgreementDeadlineTimeoutPeriod0",
            dur(p.agreement_deadline_timeout_period0),
        ),
        ("AgreementFilterTimeout", dur(p.agreement_filter_timeout)),
        (
            "AgreementFilterTimeoutPeriod0",
            dur(p.agreement_filter_timeout_period0),
        ),
        (
            "AllowZeroLocalAppRef",
            Json::Bool(p.allow_zero_local_app_ref),
        ),
        // go v5.1.0-beta parameters (vFuture only):
        (
            "AllowGroupedHeartbeats",
            Json::Bool(p.allow_grouped_heartbeats),
        ),
        (
            "DiscardFailedInnerClearStateDelta",
            Json::Bool(p.discard_failed_inner_clear_state_delta),
        ),
        (
            "EnableSigSchemeEd25519",
            Json::Bool(p.enable_sig_scheme_ed25519),
        ),
        (
            "EnableSigSchemeFalcon512",
            Json::Bool(p.enable_sig_scheme_falcon512),
        ),
        (
            "EnableSigSchemeLogicSig",
            Json::Bool(p.enable_sig_scheme_logic_sig),
        ),
        (
            "RequireLogicSigArgAccess",
            Json::Bool(p.require_logic_sig_arg_access),
        ),
        (
            "AppFlatOptInMinBalance",
            Json::Uint(p.app_flat_opt_in_min_balance),
        ),
        (
            "AppFlatParamsMinBalance",
            Json::Uint(p.app_flat_params_min_balance),
        ),
        (
            "AppForbidLowResources",
            Json::Bool(p.app_forbid_low_resources),
        ),
        ("AppSizeUpdates", Json::Bool(p.app_size_updates)),
        ("Application", Json::Bool(p.application)),
        ("Asset", Json::Bool(p.asset)),
        ("BoxByteMinBalance", Json::Uint(p.box_byte_min_balance)),
        ("BoxFlatMinBalance", Json::Uint(p.box_flat_min_balance)),
        (
            "BytesPerBoxReference",
            Json::Uint(p.bytes_per_box_reference),
        ),
        ("CatchpointLookback", Json::Uint(p.catchpoint_lookback)),
        ("CertCommitteeSize", Json::Uint(p.cert_committee_size)),
        (
            "CertCommitteeThreshold",
            Json::Uint(p.cert_committee_threshold),
        ),
        (
            "CloseRequiresBaseMinBalance",
            Json::Bool(p.close_requires_base_min_balance),
        ),
        (
            "CredentialDomainSeparationEnabled",
            Json::Bool(p.credential_domain_separation_enabled),
        ),
        (
            "DeeperBlockHeaderHistory",
            Json::Uint(p.deeper_block_header_history),
        ),
        ("DefaultKeyDilution", Json::Uint(p.default_key_dilution)),
        (
            "DefaultUpgradeWaitRounds",
            Json::Uint(p.default_upgrade_wait_rounds),
        ),
        ("DownCommitteeSize", Json::Uint(p.down_committee_size)),
        (
            "DownCommitteeThreshold",
            Json::Uint(p.down_committee_threshold),
        ),
        ("DynamicFilterTimeout", Json::Bool(p.dynamic_filter_timeout)),
        (
            "EnableAppCostPooling",
            Json::Bool(p.enable_app_cost_pooling),
        ),
        ("EnableAppVersioning", Json::Bool(p.enable_app_versioning)),
        (
            "EnableAssetCloseAmount",
            Json::Bool(p.enable_asset_close_amount),
        ),
        (
            "EnableBareBudgetError",
            Json::Bool(p.enable_bare_budget_error),
        ),
        (
            "EnableBoxRefNameError",
            Json::Bool(p.enable_box_ref_name_error),
        ),
        (
            "EnableCatchpointsWithOnlineAccounts",
            Json::Bool(p.enable_catchpoints_with_online_accounts),
        ),
        (
            "EnableCatchpointsWithSPContexts",
            Json::Bool(p.enable_catchpoints_with_sp_contexts),
        ),
        (
            "EnableInnerTransactionPooling",
            Json::Bool(p.enable_inner_transaction_pooling),
        ),
        (
            "EnableKeyregCoherencyCheck",
            Json::Bool(p.enable_keyreg_coherency_check),
        ),
        (
            "EnableLedgerDataUpdateRound",
            Json::Bool(p.enable_ledger_data_update_round),
        ),
        (
            "EnableLogicSigCostPooling",
            Json::Bool(p.enable_logicsig_cost_pooling),
        ),
        (
            "EnablePQSchemeFalcon1024",
            Json::Bool(p.enable_pq_scheme_falcon1024),
        ),
        (
            "EnablePrecheckECDSACurve",
            Json::Bool(p.enable_precheck_ecdsa_curve),
        ),
        (
            "EnableProperExtraPageAccounting",
            Json::Bool(p.enable_proper_extra_page_accounting),
        ),
        (
            "EnableSHA256TxnCommitmentHeader",
            Json::Bool(p.enable_sha256_txn_commitment_header),
        ),
        ("EnableSelectF128", Json::Bool(p.enable_select_f128)),
        (
            "EnableSha512BlockHash",
            Json::Bool(p.enable_sha512_block_hash),
        ),
        (
            "EnableStateProofKeyregCheck",
            Json::Bool(p.enable_state_proof_keyreg_check),
        ),
        (
            "EnforceAuthAddrSenderDiff",
            Json::Bool(p.enforce_auth_addr_sender_diff),
        ),
        (
            "ExcludeExpiredCirculation",
            Json::Bool(p.exclude_expired_circulation),
        ),
        ("FastRecoveryLambda", dur(p.fast_recovery_lambda)),
        ("FixTransactionLeases", Json::Bool(p.fix_transaction_leases)),
        (
            "ForceNonParticipatingFeeSink",
            Json::Bool(p.force_non_participating_fee_sink),
        ),
        ("Heartbeat", Json::Bool(p.enable_heartbeat)),
        (
            "InitialRewardsRateCalculation",
            Json::Bool(p.initial_rewards_rate_calculation),
        ),
        ("IsolateClearState", Json::Bool(p.isolate_clear_state)),
        ("LateCommitteeSize", Json::Uint(p.late_committee_size)),
        (
            "LateCommitteeThreshold",
            Json::Uint(p.late_committee_threshold),
        ),
        ("LoadTracking", Json::Bool(p.load_tracking)),
        ("LogicSigLMsig", Json::Bool(p.logic_sig_lmsig)),
        ("LogicSigMaxCost", Json::Uint(p.logic_sig_max_cost)),
        ("LogicSigMaxSize", Json::Uint(p.logic_sig_max_size)),
        ("LogicSigMsig", Json::Bool(p.logic_sig_msig)),
        ("LogicSigVersion", Json::Uint(p.logic_sig_version)),
        (
            "MaxAbsoluteExtraProgramPages",
            Json::Uint(u64::from(p.max_absolute_extra_program_pages)),
        ),
        (
            "MaxAbsoluteLogicSigProgramSize",
            Json::Uint(p.max_absolute_logic_sig_program_size),
        ),
        (
            "MaxAbsoluteTotalArgLen",
            Json::Uint(p.max_absolute_total_arg_len as u64),
        ),
        (
            "MaxAbsoluteTxnNoteBytes",
            Json::Uint(p.max_absolute_txn_note_bytes as u64),
        ),
        ("MaxAppAccess", Json::Uint(p.max_app_access as u64)),
        ("MaxAppArgs", Json::Uint(p.max_app_args as u64)),
        (
            "MaxAppBoxReferences",
            Json::Uint(p.max_app_box_references as u64),
        ),
        (
            "MaxAppBytesValueLen",
            Json::Uint(p.max_app_bytes_value_len as u64),
        ),
        ("MaxAppKeyLen", Json::Uint(p.max_app_key_len as u64)),
        ("MaxAppProgramCost", Json::Uint(p.max_app_program_cost)),
        ("MaxAppProgramLen", Json::Uint(p.max_app_program_len as u64)),
        (
            "MaxAppSumKeyValueLens",
            Json::Uint(p.max_app_sum_key_value_lens as u64),
        ),
        (
            "MaxAppTotalArgLen",
            Json::Uint(p.max_app_total_arg_len as u64),
        ),
        (
            "MaxAppTotalProgramLen",
            Json::Uint(p.max_app_total_program_len as u64),
        ),
        (
            "MaxAppTotalTxnReferences",
            Json::Uint(p.max_app_total_txn_references as u64),
        ),
        (
            "MaxAppTxnAccounts",
            Json::Uint(p.max_app_txn_accounts as u64),
        ),
        (
            "MaxAppTxnForeignApps",
            Json::Uint(p.max_app_txn_foreign_apps as u64),
        ),
        (
            "MaxAppTxnForeignAssets",
            Json::Uint(p.max_app_txn_foreign_assets as u64),
        ),
        ("MaxAppsCreated", Json::Uint(p.max_apps_created as u64)),
        ("MaxAppsOptedIn", Json::Uint(p.max_apps_opted_in as u64)),
        (
            "MaxAssetDecimals",
            Json::Uint(u64::from(p.max_asset_decimals)),
        ),
        (
            "MaxAssetNameBytes",
            Json::Uint(p.max_asset_name_bytes as u64),
        ),
        ("MaxAssetURLBytes", Json::Uint(p.max_asset_url_bytes as u64)),
        (
            "MaxAssetUnitNameBytes",
            Json::Uint(p.max_asset_unit_name_bytes as u64),
        ),
        (
            "MaxAssetsPerAccount",
            Json::Uint(u64::from(p.max_assets_per_account)),
        ),
        ("MaxBalLookback", Json::Uint(p.max_bal_lookback)),
        ("MaxBoxSize", Json::Uint(p.max_box_size)),
        (
            "MaxExtraAppProgramPages",
            Json::Uint(u64::from(p.max_extra_app_program_pages)),
        ),
        (
            "MaxGlobalSchemaEntries",
            Json::Uint(p.max_global_schema_entries),
        ),
        (
            "MaxInnerTransactions",
            Json::Uint(p.max_inner_transactions as u64),
        ),
        (
            "MaxKeyregValidPeriod",
            Json::Uint(p.max_keyreg_valid_period),
        ),
        (
            "MaxLocalSchemaEntries",
            Json::Uint(p.max_local_schema_entries),
        ),
        (
            "MaxProposedExpiredOnlineAccounts",
            Json::Uint(p.max_proposed_expired_online_accounts as u64),
        ),
        (
            "MaxTimestampIncrement",
            Json::Int(p.max_timestamp_increment),
        ),
        ("MaxTxGroupSize", Json::Uint(p.max_tx_group_size as u64)),
        ("MaxTxnBytesPerBlock", Json::Uint(p.max_txn_bytes_per_block)),
        ("MaxTxnLife", Json::Uint(p.max_txn_life)),
        ("MaxTxnNoteBytes", Json::Uint(p.max_txn_note_bytes as u64)),
        (
            "MaxUpgradeWaitRounds",
            Json::Uint(p.max_upgrade_wait_rounds),
        ),
        ("MaxVersionStringLen", Json::Uint(p.max_version_string_len)),
        (
            "MaximumMinimumBalance",
            Json::Uint(p.maximum_minimum_balance),
        ),
        ("MinBalance", Json::Uint(p.min_balance)),
        ("MinInnerApplVersion", Json::Uint(p.min_inner_appl_version)),
        ("MinTxnFee", Json::Uint(p.min_txn_fee)),
        (
            "MinUpgradeWaitRounds",
            Json::Uint(p.min_upgrade_wait_rounds),
        ),
        ("NextCommitteeSize", Json::Uint(p.next_committee_size)),
        (
            "NextCommitteeThreshold",
            Json::Uint(p.next_committee_threshold),
        ),
        ("NoEmptyLocalDeltas", Json::Bool(p.no_empty_local_deltas)),
        ("NumProposers", Json::Uint(p.num_proposers)),
        ("PaysetCommit", Json::Uint(u64::from(p.payset_commit))),
        (
            "PendingResidueRewards",
            Json::Bool(p.pending_residue_rewards),
        ),
        ("PerByteTxnSurcharge", Json::Uint(p.per_byte_txn_surcharge)),
        ("RedoCommitteeSize", Json::Uint(p.redo_committee_size)),
        (
            "RedoCommitteeThreshold",
            Json::Uint(p.redo_committee_threshold),
        ),
        ("RequireGenesisHash", Json::Bool(p.require_genesis_hash)),
        ("RewardUnit", Json::Uint(p.reward_unit)),
        (
            "RewardsCalculationFix",
            Json::Bool(p.rewards_calculation_fix),
        ),
        ("RewardsInApplyData", Json::Bool(p.rewards_in_apply_data)),
        (
            "RewardsRateRefreshInterval",
            Json::Uint(p.rewards_rate_refresh_interval),
        ),
        (
            "SchemaBytesMinBalance",
            Json::Uint(p.schema_bytes_min_balance),
        ),
        (
            "SchemaMinBalancePerEntry",
            Json::Uint(p.schema_min_balance_per_entry),
        ),
        (
            "SchemaUintMinBalance",
            Json::Uint(p.schema_uint_min_balance),
        ),
        ("SeedLookback", Json::Uint(p.seed_lookback)),
        ("SeedRefreshInterval", Json::Uint(p.seed_refresh_interval)),
        ("SoftCommitteeSize", Json::Uint(p.soft_committee_size)),
        (
            "SoftCommitteeThreshold",
            Json::Uint(p.soft_committee_threshold),
        ),
        (
            "StateProofBlockHashInLightHeader",
            Json::Bool(p.state_proof_block_hash_in_light_header),
        ),
        (
            "StateProofExcludeTotalWeightWithRewards",
            Json::Bool(p.state_proof_exclude_total_weight_with_rewards),
        ),
        ("StateProofInterval", Json::Uint(p.state_proof_interval)),
        (
            "StateProofMaxRecoveryIntervals",
            Json::Uint(p.state_proof_max_recovery_intervals),
        ),
        (
            "StateProofStrengthTarget",
            Json::Uint(p.state_proof_strength_target),
        ),
        ("StateProofTopVoters", Json::Uint(p.state_proof_top_voters)),
        (
            "StateProofUseTrackerVerification",
            Json::Bool(p.state_proof_use_tracker_verification),
        ),
        (
            "StateProofVotersLookback",
            Json::Uint(p.state_proof_voters_lookback),
        ),
        (
            "StateProofWeightThreshold",
            Json::Uint(u64::from(p.state_proof_weight_threshold)),
        ),
        (
            "SupportBecomeNonParticipatingTransactions",
            Json::Bool(p.support_become_non_participating_transactions),
        ),
        ("SupportGenesisHash", Json::Bool(p.support_genesis_hash)),
        ("SupportRekeying", Json::Bool(p.support_rekeying)),
        (
            "SupportSignedTxnInBlock",
            Json::Bool(p.support_signed_txn_in_block),
        ),
        (
            "SupportTransactionLeases",
            Json::Bool(p.support_transaction_leases),
        ),
        ("SupportTxGroups", Json::Bool(p.support_tx_groups)),
        ("UnfundedSenders", Json::Bool(p.unfunded_senders)),
        ("UnifyInnerTxIDs", Json::Bool(p.unify_inner_tx_ids)),
        ("UpgradeThreshold", Json::Uint(p.upgrade_threshold)),
        ("UpgradeVoteRounds", Json::Uint(p.upgrade_vote_rounds)),
        (
            "ApplyData",
            Json::Bool(!BEFORE_APPLY_DATA.contains(&version)),
        ),
        (
            "TxnCounter",
            Json::Bool(
                !BEFORE_APPLY_DATA.contains(&version) && !BEFORE_TXN_COUNTER.contains(&version),
            ),
        ),
        ("ApprovedUpgrades", approved_upgrades(version)),
        (
            "Bonus",
            object(vec![
                ("BaseAmount", Json::Uint(p.bonus_base_amount)),
                ("BaseRound", Json::Uint(p.bonus_base_round)),
                ("DecayInterval", Json::Uint(p.bonus_decay_interval)),
            ]),
        ),
        (
            "Payouts",
            object(vec![
                (
                    "ChallengeBits",
                    Json::Uint(u64::from(p.payouts_challenge_bits)),
                ),
                (
                    "ChallengeGracePeriod",
                    Json::Uint(p.payouts_challenge_grace_period),
                ),
                (
                    "ChallengeInterval",
                    Json::Uint(p.payouts_challenge_interval),
                ),
                ("Enabled", Json::Bool(p.payouts_enabled)),
                ("GoOnlineFee", Json::Uint(p.payouts_go_online_fee)),
                ("MaxBalance", Json::Uint(p.payouts_max_balance)),
                (
                    "MaxMarkAbsent",
                    Json::Uint(p.payouts_max_mark_absent as u64),
                ),
                ("MinBalance", Json::Uint(p.payouts_min_balance)),
                ("Percent", Json::Uint(p.payouts_percent)),
            ]),
        ),
    ];
    object(f)
}

/// `protocol.EncodeJSON(config.Consensus)`: every built-in protocol, by
/// version string.
pub fn protocols_json() -> Vec<u8> {
    let mut all: Vec<(String, ConsensusParams)> =
        c::built_in_consensus_protocols().into_iter().collect();
    all.sort_by(|a, b| a.0.cmp(&b.0));
    let doc = Json::Ordered(
        all.iter()
            .map(|(v, p)| (key(v), params_json(v, p)))
            .collect(),
    );
    encode_protocol_json(&doc)
}
