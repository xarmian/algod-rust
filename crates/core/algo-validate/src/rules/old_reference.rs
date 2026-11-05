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

//! Test-only reference copies of the validators as they were before issue
//! #2193 (verbatim from `origin/main` at the time, renamed `old_*`), and the
//! differential tests that compare their VERDICTS (accept / reject, never
//! text) with the current ones. The block-validation path is consensus
//! critical: the rule order, texts and group checks changed, the set of
//! accepted transactions and groups must not (beyond the deliberate
//! go-parity deltas named in `classify_wellformed_delta`).

#![allow(clippy::all)]

use super::*;
use algo_error::AlgoError;
use algo_types::Round;

// ── The old validators (verbatim) ─────────────────────────────────────

pub fn old_validate_transaction_wellformed(
    txn: &Transaction,
    allow_fee_pooling: bool,
    params: &ConsensusParams,
    spec: Option<&SpecialAddresses>,
) -> Result<(), AlgoError> {
    // ── Sender checks (Go: WellFormed in transaction.go) ──────────
    // Order matches Go: rewards-pool check first, then zero-sender.
    // Go checks `tx.Sender == spec.RewardsPool` unconditionally (no
    // zero-guard on the pool address).
    if let Some(sp) = spec {
        if txn.sender == sp.rewards_pool {
            return Err(AlgoError::Validation {
                message: "transaction from incentive pool is invalid".to_string(),
            });
        }
    }

    // Zero sender is always invalid.
    if txn.sender.is_zero() {
        return Err(AlgoError::Validation {
            message: "transaction cannot have zero sender".to_string(),
        });
    }

    // ── Heartbeat-specific checks (Go: HeartbeatTxnFields.wellFormed) ──
    if txn.txn_type == "hb" {
        if let Some(ref hb) = txn.heartbeat {
            // `kind` mirrors go's local `kind` variable: how (if at all) this
            // heartbeat is claiming the challenge fee discount -- used only to
            // decide whether the "must be very simple" restrictions below
            // apply. `None` means no discount is being claimed, so no
            // restriction applies.
            //
            // Post-v42 (`txn_size_pricing_enabled`): the discount is claimed
            // explicitly via `hb_challenge_discount`, regardless of grouping.
            // Pre-v42: `hb_challenge_discount` has no meaning and must not be
            // set (hard rejection, matching go's "set before it is allowed"),
            // and the discount is instead inferred from an underpaying
            // singleton heartbeat, exactly as before this field existed.
            let kind: Option<&'static str> = if params.txn_size_pricing_enabled() {
                if hb.hb_challenge_discount {
                    Some("discounted")
                } else {
                    None
                }
            } else {
                if hb.hb_challenge_discount {
                    return Err(AlgoError::Validation {
                        message: "tx.HbChallengeDiscount set before it is allowed".to_string(),
                    });
                }
                if params.enable_heartbeat && txn.group == [0u8; 32] {
                    // Fee a normal (non-discounted) heartbeat owes, computed
                    // the same way as a top-level group of one: no cost
                    // multiplier, no prior residue (go: `header.FeeContribution
                    // (proto) + 1e6` -> `MinFee().FeeForUsage(factor, 1e6, 0)`).
                    // Deliberately NOT `fee::required_fee_for_txn`, which
                    // already applies the singleton discount this inference
                    // exists to detect in the first place.
                    let undiscounted_factor = crate::fee::ONE_MICROS.saturating_add(
                        crate::fee::header_fee_contribution(txn.note.len(), params),
                    );
                    let (required_fee, _overflow) =
                        crate::fee::required_fee_for_usage(undiscounted_factor, params);
                    if txn.fee < required_fee {
                        Some(if txn.fee > 0 { "cheap" } else { "free" })
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some(kind) = kind {
                if !txn.note.is_empty() {
                    return Err(AlgoError::Validation {
                        message: format!("tx.Note is set in {kind} heartbeat"),
                    });
                }
                if txn.lease != [0u8; 32] {
                    return Err(AlgoError::Validation {
                        message: format!("tx.Lease is set in {kind} heartbeat"),
                    });
                }
                if txn.rekey_to.as_ref().is_some_and(|a| !a.is_zero()) {
                    return Err(AlgoError::Validation {
                        message: format!("tx.RekeyTo is set in {kind} heartbeat"),
                    });
                }
            }

            // Heartbeat well-formedness: proof, seed, vote_id, key_dilution
            // must be non-empty. Cryptographic verification of the
            // three-level ed25519 ephemeral key tree is done separately via
            // `verify_heartbeat_proof()` in signature.rs (called from
            // `stxnCoreChecks` equivalent).
            if hb.proof.is_none()
                || hb
                    .proof
                    .as_ref()
                    .is_some_and(|p| p.sig == [0u8; 64] && p.pk == [0u8; 32])
            {
                return Err(AlgoError::Validation {
                    message: "tx.HbProof is empty".to_string(),
                });
            }
            if hb.seed == [0u8; 32] {
                return Err(AlgoError::Validation {
                    message: "tx.HbSeed is empty".to_string(),
                });
            }
            if hb.vote_id == [0u8; 32] {
                return Err(AlgoError::Validation {
                    message: "tx.HbVoteID is empty".to_string(),
                });
            }
            if hb.key_dilution == 0 {
                return Err(AlgoError::Validation {
                    message: "tx.HbKeyDilution is zero".to_string(),
                });
            }
        } else if !params.enable_heartbeat {
            return Err(AlgoError::Validation {
                message: "heartbeat transaction not supported".to_string(),
            });
        } else {
            // heartbeat is None but heartbeats are enabled — Go's
            // tx.HeartbeatTxnFields.wellFormed() would fail on zero fields.
            return Err(AlgoError::Validation {
                message: "heartbeat transaction missing HeartbeatTxnFields".to_string(),
            });
        }
    }

    // ── Fee check ─────────────────────────────────────────────────
    // When `allow_fee_pooling` is true (caller signals txn is in a group),
    // the per-txn minimum is skipped — group-level validation handles it.
    // Ungrouped txns must always individually meet the minimum, regardless
    // of whether the protocol version enables fee pooling (Go checks this
    // in TxnGroup for both pooled and non-pooled modes).
    //
    // No separate exemption is needed here for state proofs or free/cheap/
    // discounted heartbeats: `fee::required_fee_for_txn` (via `txn_fee_factor`)
    // already computes a required fee of `0` for those cases (state proofs
    // unconditionally; heartbeats via the same discount rules enforced above),
    // so the generic comparison below naturally passes them. Special-casing
    // heartbeats here as well (as prior code did, via an `is_free_heartbeat`-
    // style flag keyed only on "fee < min_txn_fee && ungrouped") would
    // incorrectly exempt a post-v42 heartbeat that merely underpays *without*
    // requesting the explicit discount from ever having its fee checked.
    if !allow_fee_pooling {
        // Usage-based required fee (Go: `ledger/eval.CheckGroupFees`, applied
        // here to a singleton "group" of one). For an ordinary transaction
        // with no oversized/billable features this is exactly
        // `params.min_txn_fee`, so the check and its wording are unchanged
        // from the flat comparison for every transaction that isn't using
        // v42+ size pricing. A transaction with billable oversized fields
        // (large note/app-args/app-programs) requires more than the flat
        // minimum, mirroring go's `feeFactor`/`FeeForUsage`.
        let (required_fee, overflow) = crate::fee::required_fee_for_txn(txn, params);
        if overflow {
            return Err(AlgoError::Validation {
                message: "transaction required fee overflow".to_string(),
            });
        }
        if txn.fee < required_fee {
            return Err(AlgoError::Validation {
                message: format!(
                    "transaction fee {} is below minimum {}",
                    txn.fee, required_fee
                ),
            });
        }
    }

    // Last valid must be >= first valid.
    if txn.last_valid < txn.first_valid {
        return Err(AlgoError::Validation {
            message: format!(
                "last valid round {} is before first valid round {}",
                txn.last_valid, txn.first_valid
            ),
        });
    }

    // Round window must not exceed max_txn_life.
    let window = txn.last_valid.0 - txn.first_valid.0;
    if window > params.max_txn_life {
        return Err(AlgoError::Validation {
            message: format!(
                "transaction validity window {} exceeds maximum {}",
                window, params.max_txn_life
            ),
        });
    }

    // Note must not exceed the hard MaxAbsoluteTxnNoteBytes cap (Go:
    // `len(tx.Note) > proto.MaxAbsoluteTxnNoteBytes`, unconditional at every
    // protocol version). Bytes between the old free/soft cap
    // (max_txn_note_bytes) and this hard cap are well-formed but billable via
    // `fee::header_fee_contribution` (v42+ size pricing).
    let max_note_bytes = crate::fee::effective_max_note_bytes(params);
    if txn.note.len() > max_note_bytes {
        return Err(AlgoError::Validation {
            message: format!(
                "transaction note too big: {} > {}",
                txn.note.len(),
                max_note_bytes
            ),
        });
    }

    // Lease must be empty or exactly 32 bytes.
    // If leases are not supported, any non-empty lease is rejected.
    if txn.lease != [0u8; 32] {
        if !params.support_transaction_leases {
            return Err(AlgoError::Validation {
                message: "transaction tried to acquire lease but protocol does not support transaction leases".to_string(),
            });
        }
        if txn.lease.len() != MAX_LEASE_SIZE {
            return Err(AlgoError::Validation {
                message: format!(
                    "lease must be empty or exactly {} bytes, got {}",
                    MAX_LEASE_SIZE,
                    txn.lease.len()
                ),
            });
        }
    }

    // Group must be empty or exactly 32 bytes.
    // If groups are not supported, any non-empty group is rejected.
    if txn.group != [0u8; 32] {
        if !params.support_tx_groups {
            return Err(AlgoError::Validation {
                message: "transaction has group but groups not yet enabled".to_string(),
            });
        }
        if txn.group.len() != 32 {
            return Err(AlgoError::Validation {
                message: format!(
                    "group field must be empty or exactly 32 bytes, got {}",
                    txn.group.len()
                ),
            });
        }
    }

    // Rekey-to is rejected if rekeying is not supported.
    if !params.support_rekeying && txn.rekey_to.as_ref().is_some_and(|a| !a.is_zero()) {
        return Err(AlgoError::Validation {
            message: "transaction has RekeyTo set but rekeying not yet enabled".to_string(),
        });
    }

    // ── Application-call schema/size well-formedness ────────────────
    // Go: `ApplicationCallTxnFields.wellFormed` (data/transactions/application.go).
    if txn.txn_type == "appl" {
        // Go: `transaction.go`'s `WellFormed`, `case protocol.ApplicationCallTx:
        // if !proto.Application { return fmt.Errorf("application transaction
        // not supported") }` (issue #1272).
        if !params.application {
            return Err(AlgoError::Validation {
                message: "application transaction not supported".to_string(),
            });
        }
        validate_application_call_wellformed(txn, params)?;
    }

    // ── Payment well-formedness (Go: PaymentTxnFields.wellFormed, payment.go) ──
    if txn.txn_type == "pay" {
        if txn.sender == txn.close_remainder_to {
            return Err(AlgoError::Validation {
                message: format!(
                    "transaction cannot close account to its sender {}",
                    txn.sender
                ),
            });
        }
        if let Some(sp) = spec {
            if txn.sender == sp.fee_sink {
                if params.payouts_enabled {
                    return Err(AlgoError::Validation {
                        message: format!("cannot spend from fee sink address {}", txn.sender),
                    });
                }
                if txn.receiver != sp.rewards_pool {
                    return Err(AlgoError::Validation {
                        message: format!(
                            "cannot spend from fee sink's address {} to non incentive pool address {}",
                            txn.sender, txn.receiver
                        ),
                    });
                }
                if !txn.close_remainder_to.is_zero() {
                    return Err(AlgoError::Validation {
                        message: format!(
                            "cannot close fee sink {} to {}",
                            txn.sender, txn.close_remainder_to
                        ),
                    });
                }
            }
        }
    }

    // ── Asset config well-formedness (Go: AssetConfigTxnFields.wellFormed, asset.go) ──
    if txn.txn_type == "acfg" {
        // Go: `transaction.go`'s `WellFormed`, `case protocol.AssetConfigTx:
        // if !proto.Asset { return fmt.Errorf("asset transaction not
        // supported") }` (issue #1272).
        if !params.asset {
            return Err(AlgoError::Validation {
                message: "asset transaction not supported".to_string(),
            });
        }
        if let Some(ap) = &txn.asset_params {
            if ap.asset_name.len() > params.max_asset_name_bytes {
                return Err(AlgoError::Validation {
                    message: format!(
                        "transaction asset name too big: {} > {}",
                        ap.asset_name.len(),
                        params.max_asset_name_bytes
                    ),
                });
            }
            if ap.unit_name.len() > params.max_asset_unit_name_bytes {
                return Err(AlgoError::Validation {
                    message: format!(
                        "transaction asset unit name too big: {} > {}",
                        ap.unit_name.len(),
                        params.max_asset_unit_name_bytes
                    ),
                });
            }
            if ap.url.len() > params.max_asset_url_bytes {
                return Err(AlgoError::Validation {
                    message: format!(
                        "transaction asset url too big: {} > {}",
                        ap.url.len(),
                        params.max_asset_url_bytes
                    ),
                });
            }
            if ap.decimals > params.max_asset_decimals {
                return Err(AlgoError::Validation {
                    message: format!(
                        "transaction asset decimals is too high (max is {})",
                        params.max_asset_decimals
                    ),
                });
            }
        }
    }

    // ── Asset transfer well-formedness (Go: AssetTransferTxnFields.wellFormed, asset.go) ──
    if txn.txn_type == "axfer" {
        // Go: `transaction.go`'s `WellFormed`, `case protocol.AssetTransferTx:
        // if !proto.Asset { ... }` (issue #1272).
        if !params.asset {
            return Err(AlgoError::Validation {
                message: "asset transaction not supported".to_string(),
            });
        }
        if txn.xaid == 0 && txn.asset_amount != 0 {
            return Err(AlgoError::Validation {
                message: "asset ID cannot be zero".to_string(),
            });
        }
        if txn.asset_sender.as_ref().is_some_and(|a| !a.is_zero())
            && txn.asset_close_to.as_ref().is_some_and(|a| !a.is_zero())
        {
            return Err(AlgoError::Validation {
                message: "cannot close asset by clawback".to_string(),
            });
        }
    }

    // ── Asset freeze well-formedness (Go: AssetFreezeTxnFields.wellFormed, asset.go) ──
    if txn.txn_type == "afrz" {
        // Go: `transaction.go`'s `WellFormed`, `case protocol.AssetFreezeTx:
        // if !proto.Asset { ... }` (issue #1272).
        if !params.asset {
            return Err(AlgoError::Validation {
                message: "asset transaction not supported".to_string(),
            });
        }
        if txn.freeze_asset == 0 {
            return Err(AlgoError::Validation {
                message: "asset ID cannot be zero".to_string(),
            });
        }
        if txn
            .freeze_account
            .as_ref()
            .map(|a| a.is_zero())
            .unwrap_or(true)
        {
            return Err(AlgoError::Validation {
                message: "freeze account cannot be empty".to_string(),
            });
        }
    }

    // ── Keyreg well-formedness (Go: KeyregTxnFields.wellFormed, keyreg.go) ──
    if txn.txn_type == "keyreg" {
        if let Some(sp) = spec {
            if txn.sender == sp.fee_sink {
                return Err(AlgoError::Validation {
                    message: format!(
                        "cannot register participation key for fee sink's address {}",
                        txn.sender
                    ),
                });
            }
        }

        if params.enable_keyreg_coherency_check {
            if txn.vote_first > txn.vote_last {
                return Err(AlgoError::Validation {
                    message:
                        "transaction first voting round need to be less than its last voting round"
                            .to_string(),
                });
            }

            let vote_pk_empty = txn
                .vote_pk
                .as_ref()
                .map(|k| *k == [0u8; 32])
                .unwrap_or(true);
            let selection_pk_empty = txn
                .selection_pk
                .as_ref()
                .map(|k| *k == [0u8; 32])
                .unwrap_or(true);
            let coherent = (vote_pk_empty && selection_pk_empty && txn.vote_key_dilution == 0)
                || (!vote_pk_empty && !selection_pk_empty && txn.vote_key_dilution != 0);
            if !coherent {
                return Err(AlgoError::Validation {
                    message: "the following transaction fields need to be clear/set together : votekey, selkey, votekd".to_string(),
                });
            }

            if txn.vote_key_dilution == 0 {
                // Going offline: no VoteFirst/VoteLast.
                if txn.vote_first != 0 || txn.vote_last != 0 {
                    return Err(AlgoError::Validation {
                        message: "on going offline key registration transaction, the vote first and vote last fields should not be set".to_string(),
                    });
                }
            } else {
                // Going online.
                if txn.vote_last == 0 {
                    return Err(AlgoError::Validation {
                        message: "transaction tries to register keys to go online, but vote last is set to zero".to_string(),
                    });
                }
                if txn.vote_first > txn.last_valid.0 + 1 {
                    return Err(AlgoError::Validation {
                        message: "transaction tries to register keys to go online, but first voting round is beyond the round after last valid round".to_string(),
                    });
                }
            }
        }

        if txn.non_participation {
            if !params.support_become_non_participating_transactions {
                return Err(AlgoError::Validation {
                    message: "transaction tries to mark an account as nonparticipating, but that transaction is not supported".to_string(),
                });
            }
            let vote_pk_empty = txn
                .vote_pk
                .as_ref()
                .map(|k| *k == [0u8; 32])
                .unwrap_or(true);
            let selection_pk_empty = txn
                .selection_pk
                .as_ref()
                .map(|k| *k == [0u8; 32])
                .unwrap_or(true);
            if !(vote_pk_empty || selection_pk_empty) {
                return Err(AlgoError::Validation {
                    message: "transaction tries to register keys to go online, but nonparticipatory flag is set".to_string(),
                });
            }
        }

        // stateProofPKWellFormed (Go: keyreg.go).
        let state_proof_pk_empty = txn
            .state_proof_pk
            .as_ref()
            .map(|k| *k == [0u8; 64])
            .unwrap_or(true);
        if !params.enable_state_proof_keyreg_check {
            if !state_proof_pk_empty {
                return Err(AlgoError::Validation {
                    message:
                        "transaction field StateProofPK should be empty in this consensus version"
                            .to_string(),
                });
            }
        } else {
            // Go: `if proto.MaxKeyregValidPeriod != 0 && uint64(keyreg.VoteLast.SubSaturate(keyreg.VoteFirst)) > proto.MaxKeyregValidPeriod`
            // (keyreg.go, `stateProofPKWellFormed`). Runs before the
            // offline/nonparticipation StateProofPK checks below.
            if params.max_keyreg_valid_period != 0
                && txn.vote_last.saturating_sub(txn.vote_first) > params.max_keyreg_valid_period
            {
                return Err(AlgoError::Validation {
                    message: "validity period for keyreg transaction is too long".to_string(),
                });
            }

            // Go: `stateProofPKWellFormed`'s remaining three branches, checked
            // in order and mutually exclusive (each returns immediately):
            // nonparticipation -> offline (empty VotePK/SelectionPK) ->
            // online. Issue #1274 added the previously-missing third branch
            // (online transactions must NOT have an empty StateProofPK).
            if txn.non_participation {
                if !state_proof_pk_empty {
                    return Err(AlgoError::Validation {
                        message:
                            "non participation keyreg transactions should contain empty stateProofPK"
                                .to_string(),
                    });
                }
            } else {
                let vote_pk_empty = txn
                    .vote_pk
                    .as_ref()
                    .map(|k| *k == [0u8; 32])
                    .unwrap_or(true);
                let selection_pk_empty = txn
                    .selection_pk
                    .as_ref()
                    .map(|k| *k == [0u8; 32])
                    .unwrap_or(true);
                if vote_pk_empty || selection_pk_empty {
                    // Offline.
                    if !state_proof_pk_empty {
                        return Err(AlgoError::Validation {
                            message:
                                "offline keyreg transactions should contain empty stateProofPK"
                                    .to_string(),
                        });
                    }
                } else {
                    // Online: setting online cannot set an empty stateProofPK
                    // (Go: errKeyRegEmptyStateProofPK, issue #1274).
                    if state_proof_pk_empty {
                        return Err(AlgoError::Validation {
                            message:
                                "online keyreg transaction cannot have empty field StateProofPK"
                                    .to_string(),
                        });
                    }
                }
            }
        }
    }

    // ── State proof well-formedness (Go: StateProofTxnFields.wellFormed, stateproof.go) ──
    if txn.txn_type == "stpf" {
        // Go: transaction.go's WellFormed, StateProofTx case — checked before
        // StateProofTxnFields.wellFormed. State proofs are disabled entirely
        // (StateProofInterval == 0) prior to consensus v34; reject outright
        // rather than falling through to the per-field checks below.
        if params.state_proof_interval == 0 {
            return Err(AlgoError::Validation {
                message: "state proofs not supported".to_string(),
            });
        }
        if txn.sender != algo_types::Address::STATE_PROOF_SENDER {
            return Err(AlgoError::Validation {
                message: "sender must be the state-proof sender".to_string(),
            });
        }
        if txn.fee != 0 {
            return Err(AlgoError::Validation {
                message: "fee must be zero in state-proof transaction".to_string(),
            });
        }
        if !txn.note.is_empty() {
            return Err(AlgoError::Validation {
                message: "note must be empty in state-proof transaction".to_string(),
            });
        }
        if txn.group != [0u8; 32] {
            return Err(AlgoError::Validation {
                message: "group must be zero in state-proof transaction".to_string(),
            });
        }
        if txn.rekey_to.as_ref().is_some_and(|a| !a.is_zero()) {
            return Err(AlgoError::Validation {
                message: "rekey must be zero in state-proof transaction".to_string(),
            });
        }
        if txn.lease != [0u8; 32] {
            return Err(AlgoError::Validation {
                message: "lease must be zero in state-proof transaction".to_string(),
            });
        }
        // Issue #2196 (deliberate go-parity delta): go's `wellFormed` ends in
        // `checkStateProof`. Block validation ran it AFTER wellformedness via
        // `check_payset`, so the block path's verdict is unchanged; this
        // reference carries the check so the wellformed comparison stays exact.
        let default_payload = algo_types::StateProofBody::default();
        crate::checks::check_state_proof(
            txn.state_proof_type,
            txn.state_proof.as_ref().unwrap_or(&default_payload),
        )?;
    }

    // ── Cross-field type isolation (Go: transaction.go's `WellFormed`,
    // `nonZeroFields` map) ──────────────────────────────────────────
    // A transaction whose canonical wire encoding is a flat struct (mirroring
    // go-algorand's for byte-level parity) could in principle carry populated
    // fields belonging to a *different* declared type than `txn.txn_type`.
    // Go rejects this outright; issue #1273.
    check_txn_type_field_isolation(txn)?;

    Ok(())
}

pub fn old_validate_transaction_group_inner(
    txns: &[SignedTransaction],
    strict: bool,
) -> Result<(), AlgoError> {
    for_each_group(txns, |group_members| {
        let size = group_members.len();

        // On mainnet, a block may contain only a subset of group members
        // visible to us (e.g., due to field-level deserialization differences).
        // Skip validation for single-member groups in lenient (block-replay)
        // mode — the group was already validated at submission time by the
        // network. In strict (pool-admission) mode, a single member with a
        // non-zero `Group` field IS the thing we must reject: fall through to
        // the group-ID recomputation below.
        if size < 2 && !strict {
            return Ok(());
        }

        if size > MAX_GROUP_SIZE {
            return Err(AlgoError::Validation {
                message: format!(
                    "transaction group has {size} members, maximum is {MAX_GROUP_SIZE}"
                ),
            });
        }

        // Compute and verify the group ID.
        let txn_refs: Vec<Transaction> = group_members.iter().map(|s| s.txn.clone()).collect();
        let computed = compute_group_id(&txn_refs);

        let grp = &group_members[0].txn.group;
        if grp.as_ref() != computed.as_bytes().as_slice() {
            return Err(AlgoError::Validation {
                message: format!(
                    "group ID mismatch: stored {} != computed {}",
                    hex::encode(grp.as_ref()),
                    hex::encode(computed.as_bytes())
                ),
            });
        }

        Ok(())
    })
}

pub fn old_validate_transaction_group_strict(txns: &[SignedTransaction]) -> Result<(), AlgoError> {
    if txns.len() > MAX_GROUP_SIZE {
        return Err(AlgoError::Validation {
            message: format!(
                "transaction group has {} members, maximum is {MAX_GROUP_SIZE}",
                txns.len()
            ),
        });
    }
    let Some(first) = txns.first() else {
        return Ok(());
    };
    let mut ids = GroupIdChecker::new(&first.txn, txns.len());
    for (index, stx) in txns.iter().enumerate() {
        ids.check_member(index, &stx.txn)
            .map_err(|message| AlgoError::Validation { message })?;
    }
    ids.finish()
        .map_err(|message| AlgoError::Validation { message })
}

// ════════════════════════════════════════════════════════════════════
// Differential tests: the old validators (above, verbatim from origin/main
// before issue #2193) against the current ones. VERDICTS only (accept /
// reject), never text. Every difference must be one of the deliberate
// go-parity deltas named in `classify_wellformed_delta`; any other is a bug.
// ════════════════════════════════════════════════════════════════════

use algo_types::consensus::KNOWN_PROTOCOL_VERSIONS;
use algo_types::{AssetParams, BoxRef, HeartbeatProof, HeartbeatTxnFields, StateSchema};
use algo_types::{HoldingRef, LocalsRef};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, one_in: u64) -> bool {
        self.below(one_in) == 0
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
}

const SINK: Address = Address([0x51; 32]);
const POOL: Address = Address([0x52; 32]);

fn spec() -> SpecialAddresses {
    SpecialAddresses {
        fee_sink: SINK,
        rewards_pool: POOL,
    }
}

fn rand_addr(rng: &mut Rng) -> Address {
    match rng.below(8) {
        0 => Address::ZERO,
        1 => SINK,
        2 => POOL,
        3 => Address::STATE_PROOF_SENDER,
        _ => Address([1 + rng.below(6) as u8; 32]),
    }
}

fn rand_key32(rng: &mut Rng) -> Option<[u8; 32]> {
    match rng.below(3) {
        0 => None,
        1 => Some([0u8; 32]),
        _ => Some([7u8; 32]),
    }
}

fn rand_txn(rng: &mut Rng) -> Transaction {
    let ty = *rng.pick(&[
        "pay", "pay", "keyreg", "acfg", "axfer", "afrz", "appl", "appl", "stpf", "hb", "hb", "",
        "xyz",
    ]);
    let mut t = Transaction {
        txn_type: ty.into(),
        sender: if rng.chance(6) {
            rand_addr(rng)
        } else {
            Address([1; 32])
        },
        fee: *rng.pick(&[0, 999, 1000, 1000, 5000]),
        first_valid: Round(*rng.pick(&[0, 1, 500, 1000])),
        last_valid: Round(*rng.pick(&[0, 400, 1000, 1500, 2000, 100_000])),
        ..Default::default()
    };
    if rng.chance(8) {
        t.note = vec![0u8; rng.below(5000) as usize].into();
    }
    if rng.chance(8) {
        t.lease = [3u8; 32];
    }
    if rng.chance(8) {
        t.group = [4u8; 32];
    }
    if rng.chance(8) {
        t.rekey_to = Some(rand_addr(rng));
    }
    // Per-type fields, each defect with a small chance.
    if rng.chance(5) {
        t.receiver = rand_addr(rng);
        t.amount = rng.below(10);
    }
    if rng.chance(6) {
        t.close_remainder_to = rand_addr(rng);
    }
    if rng.chance(4) {
        t.vote_pk = rand_key32(rng);
        t.selection_pk = rand_key32(rng);
        t.vote_key_dilution = rng.below(3);
        t.vote_first = rng.below(1200);
        t.vote_last = rng.below(1200);
        t.non_participation = rng.chance(4);
        t.state_proof_pk = match rng.below(3) {
            0 => None,
            1 => Some([0u8; 64]),
            _ => Some([9u8; 64]),
        };
    }
    if rng.chance(4) {
        t.config_asset = rng.below(3);
        t.asset_params = Some(AssetParams {
            decimals: rng.below(25) as u32,
            asset_name: vec![0u8; rng.below(40) as usize],
            unit_name: vec![0u8; rng.below(12) as usize],
            url: vec![0u8; rng.below(120) as usize].into(),
            ..Default::default()
        });
    }
    if rng.chance(4) {
        t.xaid = rng.below(2);
        t.asset_amount = rng.below(3);
        t.asset_sender = Some(rand_addr(rng));
        t.asset_close_to = Some(rand_addr(rng));
    }
    if rng.chance(4) {
        t.freeze_asset = rng.below(2);
        t.freeze_account = Some(rand_addr(rng));
        t.asset_frozen = rng.chance(2);
    }
    if rng.chance(3) || ty == "appl" {
        t.application_id = rng.below(3);
        t.on_completion = rng.below(8);
        let prog = |rng: &mut Rng| -> Option<serde_bytes::ByteBuf> {
            match rng.below(4) {
                0 => None,
                1 => Some(vec![].into()),
                2 => Some(vec![8u8, 0x81, 1].into()),
                _ => Some(vec![*rng.pick(&[5u8, 6, 7, 8]), 0x81, 1].into()),
            }
        };
        t.approval_program = prog(rng);
        t.clear_state_program = prog(rng);
        if rng.chance(4) {
            t.extra_program_pages = rng.below(12) as u32;
        }
        if rng.chance(4) {
            t.app_arguments = Some(
                (0..rng.below(20))
                    .map(|_| Some(vec![0u8; rng.below(5000) as usize].into()))
                    .collect(),
            );
        }
        if rng.chance(4) {
            t.accounts = Some(vec![Address([2; 32]); rng.below(12) as usize]);
        }
        if rng.chance(4) {
            t.foreign_apps = Some(vec![1; rng.below(12) as usize]);
        }
        if rng.chance(4) {
            t.foreign_assets = Some(vec![1; rng.below(12) as usize]);
        }
        if rng.chance(4) {
            t.boxes = Some(
                (0..rng.below(12))
                    .map(|_| BoxRef {
                        index: rng.below(4),
                        ..Default::default()
                    })
                    .collect(),
            );
        }
        if rng.chance(4) {
            t.local_state_schema = Some(StateSchema {
                num_uint: rng.below(20),
                num_byte_slice: rng.below(20),
            });
        }
        if rng.chance(4) {
            t.global_state_schema = Some(StateSchema {
                num_uint: rng.below(70),
                num_byte_slice: rng.below(70),
            });
        }
        if rng.chance(4) {
            t.reject_version = rng.below(3);
        }
        if rng.chance(4) {
            t.access = Some(
                (0..rng.below(20))
                    .map(|_| ResourceRef {
                        address: if rng.chance(2) {
                            Address([2; 32])
                        } else {
                            Address::ZERO
                        },
                        asset: if rng.chance(4) { 3 } else { 0 },
                        app: if rng.chance(4) { 4 } else { 0 },
                        holding: rng.chance(5).then(|| HoldingRef {
                            address: rng.below(3),
                            asset: rng.below(3),
                        }),
                        locals: rng.chance(5).then(|| LocalsRef {
                            address: rng.below(3),
                            app: rng.below(3),
                        }),
                        box_ref: rng.chance(5).then(|| BoxRef {
                            index: rng.below(3),
                            ..Default::default()
                        }),
                    })
                    .collect(),
            );
        }
    }
    if ty == "stpf" || rng.chance(30) {
        t.state_proof_type = rng.below(2);
        if rng.chance(2) {
            t.sender = Address::STATE_PROOF_SENDER;
        }
    }
    if ty == "hb" || rng.chance(30) {
        let mut proof = HeartbeatProof::default();
        match rng.below(6) {
            0 => {}
            1 => proof.sig = [1; 64],
            2 => proof.pk = [1; 32],
            3 => proof.pk2 = [1; 32],
            4 => proof.pk1_sig = [1; 64],
            _ => proof.pk2_sig = [1; 64],
        }
        if rng.chance(3) {
            proof.sig = [2; 64];
            proof.pk = [2; 32];
        }
        t.heartbeat = rng
            .chance(10)
            .then_some(None)
            .unwrap_or(Some(HeartbeatTxnFields {
                address: Address([5; 32]),
                proof: if rng.chance(8) { None } else { Some(proof) },
                seed: if rng.chance(6) { [0; 32] } else { [6; 32] },
                vote_id: if rng.chance(6) { [0; 32] } else { [7; 32] },
                key_dilution: rng.below(3),
                hb_challenge_discount: rng.chance(4),
            }));
    }
    t
}

fn verdict<T>(r: &Result<T, AlgoError>) -> bool {
    r.is_ok()
}

fn message(r: &Result<(), AlgoError>) -> String {
    match r {
        Ok(()) => String::new(),
        Err(AlgoError::Validation { message }) => message.clone(),
        Err(e) => e.to_string(),
    }
}

fn partial_heartbeat_proof(t: &Transaction) -> bool {
    t.heartbeat
        .as_ref()
        .and_then(|h| h.proof.as_ref())
        .is_some_and(|p| {
            p.sig == [0; 64]
                && p.pk == [0; 32]
                && (p.pk2 != [0; 32] || p.pk1_sig != [0; 64] || p.pk2_sig != [0; 64])
        })
}

/// The deliberate go-parity verdict deltas of issue #2193, and nothing else.
/// Returns the delta's name when `(old, new)` is one of them.
fn classify_wellformed_delta(
    t: &Transaction,
    params: &ConsensusParams,
    old: &Result<(), AlgoError>,
    new: &Result<(), AlgoError>,
) -> Option<&'static str> {
    // 1. go: `if !proto.Heartbeat { return "heartbeat transaction not
    //    supported" }` is checked before the fields: an `hb` with fields on a
    //    protocol without heartbeats is no longer accepted.
    if old.is_ok()
        && new.is_err()
        && t.txn_type == "hb"
        && t.heartbeat.is_some()
        && !params.enable_heartbeat
        && message(new) == "heartbeat transaction not supported"
    {
        return Some("heartbeat gate before fields");
    }
    // 2. go: `hb.HbProof == crypto.HeartbeatProof{}` compares all five
    //    fields: a proof with only pk2/pk1_sig/pk2_sig set is not empty.
    if old.is_err()
        && new.is_ok()
        && t.txn_type == "hb"
        && partial_heartbeat_proof(t)
        && message(old) == "tx.HbProof is empty"
    {
        return Some("whole-struct heartbeat proof emptiness");
    }
    None
}

fn all_params() -> Vec<ConsensusParams> {
    KNOWN_PROTOCOL_VERSIONS
        .iter()
        .filter_map(|v| consensus_params_for_version(v))
        .collect()
}

/// (b) Thousands of randomized transactions, every consensus version of the
/// table, with and without special addresses and fee pooling.
#[test]
fn wellformed_verdicts_match_the_old_validator_on_random_transactions() {
    let params = all_params();
    assert!(params.len() > 10);
    let mut rng = Rng(0x2193_2193_2193_2193);
    let sp = spec();
    let mut deltas = std::collections::BTreeMap::<&str, u32>::new();
    let mut accepted = 0u32;
    for i in 0..60_000u32 {
        let t = rand_txn(&mut rng);
        let p = rng.pick(&params);
        let pool = rng.chance(2);
        let spec_arg = if rng.chance(4) { None } else { Some(&sp) };
        let old = old_validate_transaction_wellformed(&t, pool, p, spec_arg);
        let new = validate_transaction_wellformed(&t, pool, p, spec_arg);
        // The admission mode only ever rejects MORE (an unknown type).
        let adm = validate_transaction_wellformed_in_mode(
            &t,
            pool,
            p,
            spec_arg,
            WellFormedMode::Admission,
        );
        if new.is_err() {
            assert!(
                adm.is_err(),
                "#{i}: admission accepted what block mode rejects"
            );
        }
        if verdict(&adm) != verdict(&new) {
            assert!(
                new.is_ok()
                    && !matches!(
                        t.txn_type.as_str(),
                        "pay" | "keyreg" | "acfg" | "axfer" | "afrz" | "appl" | "stpf" | "hb"
                    ),
                "#{i}: admission differs from block mode for a known type: {t:?}"
            );
        }
        accepted += u32::from(new.is_ok());
        if verdict(&old) != verdict(&new) {
            let name = classify_wellformed_delta(&t, p, &old, &new).unwrap_or_else(|| {
                panic!(
                    "#{i}: verdict differs (old: {:?}, new: {:?}) for {t:?} under {:?}",
                    message(&old),
                    message(&new),
                    p.min_txn_fee
                )
            });
            *deltas.entry(name).or_default() += 1;
        }
    }
    // The generator must reach the accepting side too, or the test is vacuous.
    assert!(accepted > 500, "only {accepted} accepted transactions");
    println!("deliberate deltas seen: {deltas:?}");
}

fn rand_group(rng: &mut Rng) -> Vec<SignedTransaction> {
    let n = rng.below(18) as usize;
    let mut members: Vec<Transaction> = (0..n)
        .map(|i| Transaction {
            txn_type: "pay".into(),
            sender: Address([1 + (i % 5) as u8; 32]),
            fee: 1000,
            note: vec![i as u8, rng.below(256) as u8].into(),
            first_valid: Round(1),
            last_valid: Round(1000),
            amount: rng.below(5),
            ..Default::default()
        })
        .collect();
    let gid = compute_group_id(&members);
    let wrong = [0xEE; 32];
    match rng.below(8) {
        0 => {} // all zero group
        1 => members.iter_mut().for_each(|m| m.group = gid.0),
        2 => members.iter_mut().for_each(|m| m.group = wrong),
        3 => {
            // a correct group with one member dropped
            members.iter_mut().for_each(|m| m.group = gid.0);
            if !members.is_empty() {
                members.remove(rng.below(members.len() as u64) as usize);
            }
        }
        4 => {
            // a correct group, two members swapped
            members.iter_mut().for_each(|m| m.group = gid.0);
            if members.len() > 1 {
                let (a, b) = (rng.below(members.len() as u64) as usize, 0);
                members.swap(a, b);
            }
        }
        5 => {
            // a mix of correct, wrong and zero
            for m in members.iter_mut() {
                m.group = *rng.pick(&[gid.0, wrong, [0u8; 32]]);
            }
        }
        6 => {
            // correct group plus an extra, ungrouped member in the middle
            members.iter_mut().for_each(|m| m.group = gid.0);
            members.insert(
                members.len() / 2,
                Transaction {
                    txn_type: "pay".into(),
                    sender: Address([9; 32]),
                    ..Default::default()
                },
            );
        }
        _ => {
            // two interleaved groups
            let half = members.len() / 2;
            let g1 = compute_group_id(
                &members[..half]
                    .iter()
                    .step_by(1)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            members.iter_mut().enumerate().for_each(|(i, m)| {
                m.group = if i % 2 == 0 { g1.0 } else { gid.0 };
            });
        }
    }
    members
        .into_iter()
        .map(|txn| SignedTransaction {
            txn,
            ..Default::default()
        })
        .collect()
}

fn group_verdicts_agree(group: &[SignedTransaction], what: &str) {
    let old_len = old_validate_transaction_group_inner(group, false);
    let new_len = validate_transaction_group(group);
    assert_eq!(
        verdict(&old_len),
        verdict(&new_len),
        "{what}: lenient verdict differs (old {:?}, new {:?}) for a group of {}",
        old_len,
        new_len,
        group.len()
    );
    let old_strict = old_validate_transaction_group_strict(group);
    let new_strict = validate_transaction_group_strict(group);
    assert_eq!(
        verdict(&old_strict),
        verdict(&new_strict),
        "{what}: strict verdict differs (old {:?}, new {:?}) for a group of {}",
        old_strict,
        new_strict,
        group.len()
    );
}

/// (b) Randomized groups: sizes 0..17, zero, correct, wrong, mixed and
/// partial group IDs, reordered and interleaved members.
#[test]
fn group_verdicts_match_the_old_validators_on_random_groups() {
    let mut rng = Rng(0x0021_9321_9321_9321);
    let mut accepted = 0u32;
    let mut rejected = 0u32;
    for i in 0..4_000u32 {
        let g = rand_group(&mut rng);
        group_verdicts_agree(&g, &format!("random group #{i}"));
        if validate_transaction_group(&g).is_ok() {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert!(accepted > 300 && rejected > 300, "{accepted}/{rejected}");
}

fn b64(s: &str) -> Vec<u8> {
    data_encoding::BASE64.decode(s.as_bytes()).expect("base64")
}

/// (a) Every row of the go oracle (the WellFormed table, the pool-order
/// scenarios): old and new agree on every transaction and every group.
#[test]
fn verdicts_match_the_old_validators_on_every_oracle_row() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../algo-ledger/tests/fixtures/block_checkdup/oracle.json"
    );
    let o: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("oracle")).expect("json");
    let params = consensus_params_for_version(o["protocol"].as_str().unwrap()).expect("protocol");
    let sp = SpecialAddresses {
        fee_sink: Address(b64(o["fee_sink"].as_str().unwrap()).try_into().unwrap()),
        rewards_pool: Address(b64(o["rewards_pool"].as_str().unwrap()).try_into().unwrap()),
    };
    let mut groups = 0usize;
    let mut txns = 0usize;
    let mut skipped = 0usize;
    let mut check = |name: &str, rows: &[serde_json::Value]| {
        let mut group = Vec::new();
        for r in rows {
            match algo_codec::decode_signed_txn_stream(&b64(r.as_str().unwrap())) {
                Ok(mut v) => group.append(&mut v),
                Err(_) => {
                    skipped += 1;
                    return;
                }
            }
        }
        for stx in &group {
            for pool in [false, true] {
                let old = old_validate_transaction_wellformed(&stx.txn, pool, &params, Some(&sp));
                let new = validate_transaction_wellformed(&stx.txn, pool, &params, Some(&sp));
                assert_eq!(
                    verdict(&old),
                    verdict(&new),
                    "{name}: {:?} / {:?}",
                    old,
                    new
                );
                txns += 1;
            }
        }
        group_verdicts_agree(&group, name);
        groups += 1;
    };
    for r in o["wellformed"].as_array().unwrap() {
        check(r["name"].as_str().unwrap(), r["group"].as_array().unwrap());
    }
    for r in o["pool_order"].as_array().unwrap() {
        check(r["name"].as_str().unwrap(), r["group"].as_array().unwrap());
    }
    assert!(groups > 100 && txns > 200, "{groups} groups, {txns} txns");
    // Only the zero-sender rows the Rust decoder refuses (issue #2197).
    assert_eq!(skipped, 3, "undecodable oracle rows");
}

/// (c) Every real block of the repo's corpora: old and new agree on every
/// transaction (block mode, the block's special addresses, the pooling flag
/// `validate_block` passes) and on every payset's groups. None of these
/// ledgers contains a heartbeat transaction, so the two heartbeat deltas
/// cannot have changed the verdict of any block in them.
#[test]
fn verdicts_match_the_old_validators_on_every_corpus_block() {
    let mut types = std::collections::BTreeMap::<String, u32>::new();
    let mut blocks = 0usize;
    for dir in ["small", "testnet-prefix50"] {
        let path = format!(
            "{}/../../../benchmarks/corpus/{dir}/blocks.bin",
            env!("CARGO_MANIFEST_DIR")
        );
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let mut rest = bytes.strip_prefix(b"ACRPBLK1".as_slice()).expect("magic");
        while !rest.is_empty() {
            let len = u32::from_be_bytes(rest[8..12].try_into().unwrap()) as usize;
            let payload = &rest[12..12 + len];
            rest = &rest[12 + len..];
            let block = algo_codec::decode_block_response(payload)
                .expect("block")
                .block;
            let params = consensus_params_for_version(&block.current_protocol);
            let Some(params) = params else { continue };
            let sp = SpecialAddresses {
                fee_sink: block.fee_sink,
                rewards_pool: block.rewards_pool,
            };
            for stx in &block.payset {
                *types
                    .entry(stx.txn.txn_type.as_str().to_string())
                    .or_default() += 1;
                let pooled = stx.txn.group != [0u8; 32];
                let old = old_validate_transaction_wellformed(&stx.txn, pooled, &params, Some(&sp));
                let new = validate_transaction_wellformed(&stx.txn, pooled, &params, Some(&sp));
                assert_eq!(
                    verdict(&old),
                    verdict(&new),
                    "{dir} round {}",
                    block.round.0
                );
            }
            let old = old_validate_transaction_group_inner(&block.payset, false);
            let new = validate_transaction_group(&block.payset);
            assert_eq!(
                verdict(&old),
                verdict(&new),
                "{dir} round {}",
                block.round.0
            );
            blocks += 1;
        }
    }
    assert!(blocks > 50, "{blocks} blocks");
    assert!(types.get("pay").copied().unwrap_or(0) > 100, "{types:?}");
    assert!(
        !types.contains_key("hb"),
        "a corpus block holds a heartbeat: {types:?}"
    );
    println!("corpus blocks: {blocks}, txn types: {types:?}");
}

/// Issue #2193 (consensus-visible deltas): go's real `Transaction.WellFormed`
/// on a heartbeat and a payment, for EVERY consensus version go knows, against
/// the Rust validator under the same version's parameters. Pins the two
/// heartbeat deltas (the protocol gate before the fields; a proof is empty
/// only when all five of its fields are zero) with go's own output, with the
/// gate off (every protocol before v40) and on.
#[test]
fn wellformed_matches_go_on_every_consensus_version() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../algo-ledger/tests/fixtures/block_checkdup/oracle.json"
    );
    let o: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("oracle")).expect("json");
    let sp = SpecialAddresses {
        fee_sink: Address(b64(o["fee_sink"].as_str().unwrap()).try_into().unwrap()),
        rewards_pool: Address(b64(o["rewards_pool"].as_str().unwrap()).try_into().unwrap()),
    };
    let mut gate_off = 0;
    let mut gate_on = 0;
    let mut unknown_to_rust = std::collections::BTreeSet::new();
    let mut mismatches = Vec::new();
    for r in o["wellformed_proto"].as_array().unwrap() {
        let version = r["protocol"].as_str().unwrap();
        let name = r["name"].as_str().unwrap();
        let Some(params) = consensus_params_for_version(version) else {
            unknown_to_rust.insert(version.to_string());
            continue;
        };
        let mut stx =
            algo_codec::decode_signed_txn_stream(&b64(r["txn"].as_str().unwrap())).expect("txn");
        let txn = stx.remove(0).txn;
        let want = r["error"].as_str().unwrap();
        for mode in [WellFormedMode::Block, WellFormedMode::Admission] {
            let got = message(&validate_transaction_wellformed_in_mode(
                &txn,
                true,
                &params,
                Some(&sp),
                mode,
            ));
            if got != want {
                mismatches.push(format!("{name} @ {version}: go {want:?}, rust {got:?}"));
            }
        }
        if name == "proto_hb_valid_fields" {
            if params.enable_heartbeat {
                gate_on += 1;
                assert_eq!(want, "", "{version}: go rejects a valid heartbeat");
            } else {
                gate_off += 1;
                assert_eq!(want, "heartbeat transaction not supported", "{version}");
            }
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    // The gate is exercised on both sides, and Rust's table agrees with go's
    // `Heartbeat` flag for every version both know.
    assert!(
        gate_on >= 3 && gate_off >= 20,
        "{gate_on} on / {gate_off} off"
    );
    println!("versions go knows and the Rust table does not: {unknown_to_rust:?}");
}
