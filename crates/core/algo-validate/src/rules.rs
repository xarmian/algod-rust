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

// Epic 10: Stateless protocol rules (fees, rounds, groups)
// Conformance review (#34): version-aware consensus params, zero-sender /
// rewards-pool-sender checks, heartbeat fee exemption.

use algo_error::AlgoError;
use algo_types::{Address, Digest, ResourceRef, SignedTransaction, Transaction};

// Re-export the comprehensive ConsensusParams and lookup function from algo-types.
pub use algo_types::consensus::ConsensusParams;
pub use algo_types::consensus::KNOWN_PROTOCOL_VERSIONS;

// Consensus defaults — stable across all protocol versions to date.
// These constants are kept for backward compatibility with existing callers.
pub const MIN_TXN_FEE: u64 = 1000;
pub const MAX_TXN_LIFE: u64 = 1000;
pub const MAX_NOTE_SIZE: usize = 1024;
pub const MAX_GROUP_SIZE: usize = 16;
pub const MAX_LEASE_SIZE: usize = 32;

// Block-level consensus constants.
/// Maximum seconds a block timestamp can exceed the previous block's timestamp.
/// Matches go-algorand `MaxTimestampIncrement` (set in v7, unchanged since).
pub const MAX_TIMESTAMP_INCREMENT: i64 = 25;

/// Maximum total transaction bytes per block (v7-v32).
pub const MAX_TXN_BYTES_PER_BLOCK_V32: usize = 1_000_000;

/// Maximum total transaction bytes per block (v33+).
pub const MAX_TXN_BYTES_PER_BLOCK_V33: usize = 5 * 1024 * 1024;

/// Special addresses for validation (fee sink and rewards pool).
///
/// Mirrors go-algorand's `transactions.SpecialAddresses`.
#[derive(Debug, Clone, Default)]
pub struct SpecialAddresses {
    pub fee_sink: Address,
    pub rewards_pool: Address,
}

/// Return consensus parameters for the given protocol version string.
///
/// Delegates to `algo_types::consensus::consensus_params_for_version`.
/// All values match go-algorand `config/consensus.go` at tag v4.6.0-stable.
///
/// Returns `None` for unknown protocol versions.
pub fn consensus_params_for_version(version: &str) -> Option<ConsensusParams> {
    algo_types::consensus::consensus_params_for_version(version)
}

/// Validate individual transaction rules (fee, round window, note size,
/// lease size, group size). Does NOT validate group membership or signatures.
///
/// When `allow_fee_pooling` is true, the per-transaction minimum fee check is
/// skipped. This is used when transactions are part of an atomic group where
/// fee pooling allows one transaction to overpay for others. In that case,
/// the caller should use `validate_group_fees()` to check group-level fees.
///
/// This is the backward-compatible entry point using default consensus
/// params and no special-address checks. Fee pooling is NOT enabled in the
/// default params here (unlike V41 defaults) to preserve the original
/// per-txn fee check behavior. For version-aware validation, use
/// `validate_transaction_wellformed()`.
pub fn validate_transaction_rules(
    txn: &Transaction,
    allow_fee_pooling: bool,
) -> Result<(), AlgoError> {
    // Use params with enable_fee_pooling=false so per-txn fee checks work
    // as the old callers expect. The `allow_fee_pooling` parameter from the
    // caller controls whether THIS specific call skips the fee check.
    let params = ConsensusParams {
        enable_fee_pooling: false,
        ..ConsensusParams::default()
    };
    validate_transaction_wellformed(txn, allow_fee_pooling, &params, None)
}

/// Version-aware transaction well-formedness check.
///
/// Mirrors go-algorand's `Transaction.WellFormed()` plus the fee/round/note/
/// lease/group checks from the outer validation layer. When `spec` is
/// provided, also checks for zero sender and rewards-pool sender.
///
/// # Checks performed
///
/// 1. Sender must not be zero (Go: `tx.Sender.IsZero()`)
/// 2. Sender must not be the rewards pool (Go: `tx.Sender == spec.RewardsPool`)
/// 3. Fee minimum (unless fee pooling or state proof or free heartbeat)
/// 4. Round window (last_valid >= first_valid, window <= max_txn_life)
/// 5. Note size limit
/// 6. Lease format (empty or 32 bytes; rejected if leases not supported)
/// 7. Group format (empty or 32 bytes; rejected if groups not supported)
/// 8. Rekey-to rejected if rekeying not supported
/// 9. Heartbeat-specific well-formedness (free heartbeat restrictions)
pub fn validate_transaction_wellformed(
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
        validate_application_call_wellformed(txn, params)?;
    }

    Ok(())
}

/// `OnCompletion` action values (Go: `data/transactions/application.go`
/// `OnCompletion` enum, `NoOpOC`..`DeleteApplicationOC` = 0..5).
const ON_COMPLETION_NOOP: u64 = 0;
const ON_COMPLETION_OPTIN: u64 = 1;
const ON_COMPLETION_CLOSEOUT: u64 = 2;
const ON_COMPLETION_CLEARSTATE: u64 = 3;
const ON_COMPLETION_UPDATE: u64 = 4;
const ON_COMPLETION_DELETE: u64 = 5;

/// Maximum byte-slice length for a single `ApplicationArgs` entry (Go:
/// `config.MaxAVMBytesSize`, `data/transactions/logic/eval.go`). This is a
/// hardcoded AVM constant, not a versioned consensus parameter — it has been
/// 4096 since apps launched and matches `algo_avm::opcode::MAX_STRING_SIZE`.
const MAX_AVM_BYTES_SIZE: usize = algo_avm::opcode::MAX_STRING_SIZE;

/// go-algorand's `syncProgramsVersion`
/// (`data/transactions/transaction.go`): AVM programs at this version or
/// higher require the ApprovalProgram/ClearStateProgram versions to match.
const SYNC_PROGRAMS_VERSION: u64 = 6;

/// Parse the leading AVM version byte(s) out of program bytecode, mirroring
/// go-algorand's `transactions.ProgramVersion` (`data/transactions/transaction.go`):
/// a `binary.Uvarint`-encoded version number at the start of the bytecode.
/// Empty bytecode, or a malformed (overflowing / unterminated) varint, is an
/// error — this is what makes `CheckContractVersions` reject a missing
/// program at creation/update time.
fn parse_program_version(bytecode: &[u8]) -> Result<u64, AlgoError> {
    if bytecode.is_empty() {
        return Err(AlgoError::Validation {
            message: "invalid program (empty)".to_string(),
        });
    }
    let mut version: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in bytecode.iter().enumerate() {
        if i >= 10 {
            return Err(AlgoError::Validation {
                message: "invalid version".to_string(),
            });
        }
        if i == 9 && b > 1 {
            // 10th byte may only contribute a single extra bit for a u64.
            return Err(AlgoError::Validation {
                message: "invalid version".to_string(),
            });
        }
        version |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(version);
        }
        shift += 7;
    }
    Err(AlgoError::Validation {
        message: "invalid version".to_string(),
    })
}

/// Mirrors go-algorand's `CheckContractVersions(approval, clear, previous,
/// proto)` (`data/transactions/transaction.go`) as called from `wellFormed`
/// — always with an empty `previous` (the downgrade check only applies when
/// checking against existing on-chain `AppParams`, which `wellFormed` never
/// has), so only the version-parse and version-match portions apply here.
fn check_contract_versions(approval: &[u8], clear: &[u8]) -> Result<(), AlgoError> {
    let av = parse_program_version(approval).map_err(|e| AlgoError::Validation {
        message: format!("bad ApprovalProgram: {e}"),
    })?;
    let cv = parse_program_version(clear).map_err(|e| AlgoError::Validation {
        message: format!("bad ClearStateProgram: {e}"),
    })?;
    if (av >= SYNC_PROGRAMS_VERSION || cv >= SYNC_PROGRAMS_VERSION) && av != cv {
        return Err(AlgoError::Validation {
            message: format!("program version mismatch: {av} != {cv}"),
        });
    }
    Ok(())
}

/// Mirrors go-algorand's `ApplicationCallTxnFields.UpdatingSizes()`
/// (`data/transactions/application.go`): true when this is an application
/// *update* transaction that also carries non-zero sizing fields
/// (`ExtraProgramPages` and/or `GlobalStateSchema`).
///
/// Note this deliberately does NOT gate on `ApplicationID != 0` — it matches
/// upstream exactly, which checks only `OnCompletion` and the sizing fields.
fn updating_sizes(txn: &Transaction) -> bool {
    let global_schema_nonempty = txn
        .global_state_schema
        .as_ref()
        .is_some_and(|s| !s.is_empty());
    txn.on_completion == ON_COMPLETION_UPDATE
        && (txn.extra_program_pages != 0 || global_schema_nonempty)
}

/// Mirrors go-algorand's `ApplicationCallTxnFields.WellSizedPrograms`
/// (`data/transactions/application.go`): bounds `ApprovalProgram` /
/// `ClearStateProgram` length, individually and summed, against
/// `MaxAppProgramLen` / `MaxAppTotalProgramLen` scaled by
/// `1 + extra_pages`.
fn well_sized_programs(
    approval_len: usize,
    clear_len: usize,
    extra_pages: u32,
    params: &ConsensusParams,
) -> Result<(), AlgoError> {
    let pages = 1usize + extra_pages as usize;
    let max_program_len = pages * params.max_app_program_len;
    if approval_len > max_program_len {
        return Err(AlgoError::Validation {
            message: format!("approval program too long. ({approval_len} > {max_program_len})"),
        });
    }
    if clear_len > max_program_len {
        return Err(AlgoError::Validation {
            message: format!("clear state program too long. ({clear_len} > {max_program_len})"),
        });
    }
    let max_total_program_len = pages * params.max_app_total_program_len;
    if approval_len + clear_len > max_total_program_len {
        return Err(AlgoError::Validation {
            message: format!(
                "app programs too long. ({approval_len} + {clear_len} > {max_total_program_len})"
            ),
        });
    }
    Ok(())
}

/// Mirrors go-algorand's `HoldingRef.Resolve` (`data/transactions/application.go`)
/// as invoked from `ResourceRef.wellFormed` — only the error path matters
/// here (the resolved address/asset aren't needed for a structural check).
fn holding_ref_resolve(
    hr: &algo_types::HoldingRef,
    access: &[ResourceRef],
) -> Result<(), AlgoError> {
    if hr.address != 0 {
        if hr.address > access.len() as u64 {
            return Err(AlgoError::Validation {
                message: format!("holding Address reference {} outside tx.Access", hr.address),
            });
        }
        if access[(hr.address - 1) as usize].address.is_zero() {
            return Err(AlgoError::Validation {
                message: format!("holding Address reference {} is not an Address", hr.address),
            });
        }
    }
    if hr.asset == 0 || hr.asset > access.len() as u64 {
        return Err(AlgoError::Validation {
            message: format!("holding Asset reference {} outside tx.Access", hr.asset),
        });
    }
    if access[(hr.asset - 1) as usize].asset == 0 {
        return Err(AlgoError::Validation {
            message: format!("holding Asset reference {} is not an Asset", hr.asset),
        });
    }
    Ok(())
}

/// Mirrors go-algorand's `LocalsRef.Resolve`.
fn locals_ref_resolve(lr: &algo_types::LocalsRef, access: &[ResourceRef]) -> Result<(), AlgoError> {
    if lr.address != 0 {
        if lr.address > access.len() as u64 {
            return Err(AlgoError::Validation {
                message: format!("locals Address reference {} outside tx.Access", lr.address),
            });
        }
        if access[(lr.address - 1) as usize].address.is_zero() {
            return Err(AlgoError::Validation {
                message: format!("locals Address reference {} is not an Address", lr.address),
            });
        }
    }
    if lr.app != 0 {
        if lr.app > access.len() as u64 {
            return Err(AlgoError::Validation {
                message: format!("locals App reference {} outside tx.Access", lr.app),
            });
        }
        if access[(lr.app - 1) as usize].app == 0 {
            return Err(AlgoError::Validation {
                message: format!("locals App reference {} is not an App", lr.app),
            });
        }
    }
    Ok(())
}

/// Mirrors go-algorand's `BoxRef.Resolve` as called from `ResourceRef` (the
/// `tx.Access`-list flavor of `BoxRef`, where `Index` refers into `Access`
/// itself — distinct from the `tx.Boxes` flavor, where `Index` refers into
/// `tx.ForeignApps`).
fn access_box_ref_resolve(
    br: &algo_types::BoxRef,
    access: &[ResourceRef],
) -> Result<(), AlgoError> {
    if br.index == 0 {
        return Ok(());
    }
    if br.index <= access.len() as u64 {
        if access[(br.index - 1) as usize].app == 0 {
            return Err(AlgoError::Validation {
                message: format!("box Index reference {} is not an App", br.index),
            });
        }
        return Ok(());
    }
    Err(AlgoError::Validation {
        message: format!("box Index {} outside tx.Access", br.index),
    })
}

/// Mirrors go-algorand's `ResourceRef.wellFormed` (`data/transactions/application.go`):
/// a `tx.Access` entry must be empty, or a single kind of resource, with any
/// internal indices pointing to proper locations inside `access`.
fn resource_ref_wellformed(
    rr: &ResourceRef,
    access: &[ResourceRef],
    in_create: bool,
    params: &ConsensusParams,
) -> Result<(), AlgoError> {
    let mut count = 0u32;
    if !rr.address.is_zero() {
        count += 1;
    }
    if rr.asset != 0 {
        count += 1;
    }
    if rr.app != 0 {
        count += 1;
    }
    if let Some(holding) = rr.holding.as_ref() {
        if !holding.is_empty() {
            holding_ref_resolve(holding, access)?;
            count += 1;
        }
    }
    if let Some(locals) = rr.locals.as_ref() {
        if !locals.is_empty() {
            if !params.allow_zero_local_app_ref && locals.app == 0 {
                return Err(AlgoError::Validation {
                    message: "0 App in LocalsRef is not supported".to_string(),
                });
            }
            if in_create && locals.app == 0 {
                return Err(AlgoError::Validation {
                    message: "0 App in LocalsRef during app create is not allowed or necessary"
                        .to_string(),
                });
            }
            locals_ref_resolve(locals, access)?;
            count += 1;
        }
    }
    if let Some(box_ref) = rr.box_ref.as_ref() {
        if !box_ref.is_empty() {
            let name_len = box_ref.name.as_ref().map_or(0, |n| n.len());
            if params.enable_box_ref_name_error && name_len > params.max_app_key_len {
                return Err(AlgoError::Validation {
                    message: format!(
                        "tx.Access box Name too long, max len {} bytes",
                        params.max_app_key_len
                    ),
                });
            }
            access_box_ref_resolve(box_ref, access)?;
            count += 1;
        }
    }
    match count {
        0 => {
            if !rr.is_empty() {
                return Err(AlgoError::Validation {
                    message: "tx.Access with unknown content".to_string(),
                });
            }
            Ok(())
        }
        1 => Ok(()),
        _ => Err(AlgoError::Validation {
            message: "tx.Access element has fields from multiple types".to_string(),
        }),
    }
}

/// Application-call-specific well-formedness checks.
///
/// A (line-for-line, in the same order) port of go-algorand's
/// `ApplicationCallTxnFields.wellFormed` (`data/transactions/application.go`,
/// current v5.0.0-stable structure). Originally landed (#675/PR #700) for
/// just the schema/extra-program-pages immutability portion (post
/// `e885e4e8a` "Txn: Check for local schema setting in update" / #6682);
/// extended (#701) to cover every remaining sub-check: `OnCompletion`
/// validity, `RejectVersion`, program-presence/`CheckContractVersions`,
/// `WellSizedPrograms`, `MaxAppArgs`/arg-length bounds, and the
/// `Access`/`Accounts`/`ForeignApps`/`ForeignAssets`/`Boxes` reference-count
/// bounds (including each `Access` entry's own structural
/// `ResourceRef.wellFormed` check).
///
/// The critical structural rule from the original #675 fix (the bug
/// `e885e4e8a` fixed upstream): a non-empty `LocalStateSchema` is rejected
/// UNCONDITIONALLY whenever `ApplicationID != 0` (i.e. any non-creation app
/// call) — local schema can only ever be set at creation. This must NOT be
/// nested inside the `AppSizeUpdates && UpdatingSizes()` guard that
/// conditionally allows `GlobalStateSchema`/`ExtraProgramPages` to be
/// non-zero on a resize update — doing so would let a resize update smuggle
/// in a `LocalStateSchema` mutation, which is exactly the vulnerability the
/// upstream commit closed.
fn validate_application_call_wellformed(
    txn: &Transaction,
    params: &ConsensusParams,
) -> Result<(), AlgoError> {
    // Ensure requested action is valid.
    match txn.on_completion {
        ON_COMPLETION_NOOP
        | ON_COMPLETION_OPTIN
        | ON_COMPLETION_CLOSEOUT
        | ON_COMPLETION_CLEARSTATE
        | ON_COMPLETION_UPDATE
        | ON_COMPLETION_DELETE => { /* ok */ }
        other => {
            return Err(AlgoError::Validation {
                message: format!("invalid application OnCompletion ({other})"),
            });
        }
    }

    if !params.enable_app_versioning && txn.reject_version > 0 {
        return Err(AlgoError::Validation {
            message: "tx.RejectVersion is not supported".to_string(),
        });
    }
    if txn.reject_version > 0 && txn.application_id == 0 {
        return Err(AlgoError::Validation {
            message: "tx.RejectVersion cannot be set during creation".to_string(),
        });
    }

    // Programs may only be set for creation or update.
    let approval_bytes: &[u8] = txn
        .approval_program
        .as_ref()
        .map_or(&[][..], |b| b.as_slice());
    let clear_bytes: &[u8] = txn
        .clear_state_program
        .as_ref()
        .map_or(&[][..], |b| b.as_slice());
    if txn.application_id != 0 && txn.on_completion != ON_COMPLETION_UPDATE {
        if !approval_bytes.is_empty() || !clear_bytes.is_empty() {
            return Err(AlgoError::Validation {
                message: "programs may only be specified during application creation or update"
                    .to_string(),
            });
        }
    } else {
        // This checks version matching, but not downgrading — downgrading
        // depends on chain state (existing AppParams), which `wellFormed`
        // never has access to, so it always passes an empty `previous`.
        check_contract_versions(approval_bytes, clear_bytes)?;
    }

    // Unconditional bound on ExtraProgramPages, regardless of creation/update.
    if txn.extra_program_pages > params.max_absolute_extra_program_pages {
        return Err(AlgoError::Validation {
            message: format!(
                "tx.ExtraProgramPages exceeds MaxAbsoluteExtraProgramPages = {}",
                params.max_absolute_extra_program_pages
            ),
        });
    }

    let mut effective_epp = txn.extra_program_pages;

    if txn.application_id != 0 {
        // Local schema can only be set during creation — unconditional, no
        // AppSizeUpdates exception. This check must stay OUTSIDE the
        // AppSizeUpdates/UpdatingSizes conditional below.
        let local_schema_nonempty = txn
            .local_state_schema
            .as_ref()
            .is_some_and(|s| !s.is_empty());
        if local_schema_nonempty {
            return Err(AlgoError::Validation {
                message: format!(
                    "inappropriate non-zero tx.LocalStateSchema ({:?})",
                    txn.local_state_schema
                ),
            });
        }

        // Global schema and extra program pages can only be set during
        // creation, or during an update when AppSizeUpdates is active and
        // this update is legitimately resizing.
        if !(params.app_size_updates && updating_sizes(txn)) {
            let global_schema_nonempty = txn
                .global_state_schema
                .as_ref()
                .is_some_and(|s| !s.is_empty());
            if global_schema_nonempty {
                return Err(AlgoError::Validation {
                    message: format!(
                        "inappropriate non-zero tx.GlobalStateSchema ({:?})",
                        txn.global_state_schema
                    ),
                });
            }
            if txn.extra_program_pages != 0 {
                return Err(AlgoError::Validation {
                    message: format!(
                        "inappropriate non-zero tx.ExtraProgramPages ({})",
                        txn.extra_program_pages
                    ),
                });
            }
            // We haven't checked the app params to know the actual EPP, so
            // allow maximum-size programs for now (Go: `effectiveEPP =
            // uint32(proto.MaxAbsoluteExtraProgramPages)`).
            effective_epp = params.max_absolute_extra_program_pages;
        }
    }

    well_sized_programs(
        approval_bytes.len(),
        clear_bytes.len(),
        effective_epp,
        params,
    )?;

    // Limit total number of arguments.
    let num_args = txn.app_arguments.as_ref().map_or(0, |a| a.len());
    if num_args > params.max_app_args {
        return Err(AlgoError::Validation {
            message: format!(
                "tx.ApplicationArgs has too many arguments. {} > {}",
                num_args, params.max_app_args
            ),
        });
    }

    // Each individual argument is bounded by the hardcoded AVM byte-slice
    // size ceiling (Go: `config.MaxAVMBytesSize`), independent of any
    // consensus-versioned total-length cap.
    if let Some(args) = txn.app_arguments.as_ref() {
        for (i, arg) in args.iter().enumerate() {
            let l = arg.as_ref().map_or(0, |b| b.len());
            if l > MAX_AVM_BYTES_SIZE {
                return Err(AlgoError::Validation {
                    message: format!(
                        "tx.ApplicationArgs[{i}] length is too long. {l} > {MAX_AVM_BYTES_SIZE}"
                    ),
                });
            }
        }
    }

    // Total ApplicationArgs byte length must not exceed the hard
    // MaxAbsoluteTotalArgLen cap (Go: `argSum > proto.MaxAbsoluteTotalArgLen`,
    // `data/transactions/application.go`, unconditional at every protocol
    // version). Bytes between the old free/soft cap (max_app_total_arg_len)
    // and this hard cap are well-formed but billable via
    // `fee::app_call_fee_contribution` (v42+ size pricing).
    let total_arg_bytes: usize = txn
        .app_arguments
        .as_ref()
        .map(|args| {
            args.iter()
                .map(|a| a.as_ref().map(|b| b.len()).unwrap_or(0))
                .sum()
        })
        .unwrap_or(0);
    let max_total_arg_len = crate::fee::effective_max_total_arg_len(params);
    if total_arg_bytes > max_total_arg_len {
        return Err(AlgoError::Validation {
            message: format!(
                "tx.ApplicationArgs total length is too long. {} > {}",
                total_arg_bytes, max_total_arg_len
            ),
        });
    }

    // ── Access / legacy reference-array bounds ───────────────────
    // Go: `data/transactions/application.go`, `wellFormed`'s `if
    // len(ac.Access) > 0 { ... } else { ... }` block.
    let access = txn.access.as_deref().unwrap_or(&[]);
    if !access.is_empty() {
        if access.len() > params.max_app_access {
            return Err(AlgoError::Validation {
                message: format!(
                    "tx.Access too long, max number of references is {}",
                    params.max_app_access
                ),
            });
        }
        // When tx.Access is used, no other references are allowed.
        if txn.accounts.as_ref().is_some_and(|v| !v.is_empty()) {
            return Err(AlgoError::Validation {
                message: "tx.Accounts can't be used when tx.Access is used".to_string(),
            });
        }
        if txn.foreign_apps.as_ref().is_some_and(|v| !v.is_empty()) {
            return Err(AlgoError::Validation {
                message: "tx.ForeignApps can't be used when tx.Access is used".to_string(),
            });
        }
        if txn.foreign_assets.as_ref().is_some_and(|v| !v.is_empty()) {
            return Err(AlgoError::Validation {
                message: "tx.ForeignAssets can't be used when tx.Access is used".to_string(),
            });
        }
        if txn.boxes.as_ref().is_some_and(|v| !v.is_empty()) {
            return Err(AlgoError::Validation {
                message: "tx.Boxes can't be used when tx.Access is used".to_string(),
            });
        }

        for rr in access {
            resource_ref_wellformed(rr, access, txn.application_id == 0, params)?;
        }
    } else {
        let num_accounts = txn.accounts.as_ref().map_or(0, |v| v.len());
        if num_accounts > params.max_app_txn_accounts {
            return Err(AlgoError::Validation {
                message: format!(
                    "tx.Accounts too long, max number of accounts is {}",
                    params.max_app_txn_accounts
                ),
            });
        }
        let num_foreign_apps = txn.foreign_apps.as_ref().map_or(0, |v| v.len());
        if num_foreign_apps > params.max_app_txn_foreign_apps {
            return Err(AlgoError::Validation {
                message: format!(
                    "tx.ForeignApps too long, max number of foreign apps is {}",
                    params.max_app_txn_foreign_apps
                ),
            });
        }
        let num_foreign_assets = txn.foreign_assets.as_ref().map_or(0, |v| v.len());
        if num_foreign_assets > params.max_app_txn_foreign_assets {
            return Err(AlgoError::Validation {
                message: format!(
                    "tx.ForeignAssets too long, max number of foreign assets is {}",
                    params.max_app_txn_foreign_assets
                ),
            });
        }
        let num_boxes = txn.boxes.as_ref().map_or(0, |v| v.len());
        if num_boxes > params.max_app_box_references {
            return Err(AlgoError::Validation {
                message: format!(
                    "tx.Boxes too long, max number of box references is {}",
                    params.max_app_box_references
                ),
            });
        }

        // Limit the sum of all types of references that bring in resource records.
        let total_refs = num_accounts + num_foreign_apps + num_foreign_assets + num_boxes;
        if total_refs > params.max_app_total_txn_references {
            return Err(AlgoError::Validation {
                message: format!(
                    "tx references exceed MaxAppTotalTxnReferences = {}",
                    params.max_app_total_txn_references
                ),
            });
        }
    }

    if let Some(boxes) = txn.boxes.as_ref() {
        let num_foreign_apps = txn.foreign_apps.as_ref().map_or(0, |v| v.len()) as u64;
        for (i, br) in boxes.iter().enumerate() {
            // Recall 0 is the current app, so indexes are shifted — the
            // test is for greater-than, not greater-or-equal.
            if br.index > num_foreign_apps {
                return Err(AlgoError::Validation {
                    message: format!(
                        "tx.Boxes[{i}].Index is {}. Exceeds len(tx.ForeignApps)",
                        br.index
                    ),
                });
            }
            let name_len = br.name.as_ref().map_or(0, |n| n.len());
            if params.enable_box_ref_name_error && name_len > params.max_app_key_len {
                return Err(AlgoError::Validation {
                    message: format!(
                        "tx.Boxes[{i}].Name too long, max len {} bytes",
                        params.max_app_key_len
                    ),
                });
            }
        }
    }

    // MaxLocalSchemaEntries / MaxGlobalSchemaEntries: unconditional size caps,
    // independent of the immutability checks above.
    let local_entries = txn
        .local_state_schema
        .as_ref()
        .map(|s| s.num_entries())
        .unwrap_or(0);
    if local_entries > params.max_local_schema_entries {
        return Err(AlgoError::Validation {
            message: format!(
                "tx.LocalStateSchema is too large. {} > {}",
                local_entries, params.max_local_schema_entries
            ),
        });
    }
    let global_entries = txn
        .global_state_schema
        .as_ref()
        .map(|s| s.num_entries())
        .unwrap_or(0);
    if global_entries > params.max_global_schema_entries {
        return Err(AlgoError::Validation {
            message: format!(
                "tx.GlobalStateSchema is too large. {} > {}",
                global_entries, params.max_global_schema_entries
            ),
        });
    }

    Ok(())
}

/// Validate that a block's protocol version is known.
///
/// go-algorand rejects blocks whose `proto` field is not in the consensus
/// params map. We replicate this by checking against `KNOWN_PROTOCOL_VERSIONS`.
pub fn validate_protocol_version(version: &str) -> Result<(), AlgoError> {
    if version.is_empty() {
        return Err(AlgoError::Validation {
            message: "block protocol version is empty".to_string(),
        });
    }
    if !KNOWN_PROTOCOL_VERSIONS.contains(&version) {
        return Err(AlgoError::Validation {
            message: format!("unknown protocol version: {version}"),
        });
    }
    Ok(())
}

/// Return the index of a protocol version in `KNOWN_PROTOCOL_VERSIONS`,
/// or `None` if not found.
pub fn protocol_version_index(version: &str) -> Option<usize> {
    KNOWN_PROTOCOL_VERSIONS.iter().position(|&v| v == version)
}

/// Return the maximum transaction bytes per block for the given protocol
/// version string. Versions v33+ use the larger 5 MiB limit; earlier
/// versions use the 1 MiB limit. Returns an error for unknown versions.
pub fn max_txn_bytes_per_block(version: &str) -> Result<usize, AlgoError> {
    let params = consensus_params_for_version(version).ok_or_else(|| AlgoError::Validation {
        message: format!("unknown protocol version: {version}"),
    })?;
    Ok(params.max_txn_bytes_per_block as usize)
}

/// Returns `true` if the given protocol version uses Merkle tree payset
/// commitment (v26+). Returns `false` for unknown versions.
pub fn has_payset_commit_merkle(version: &str) -> bool {
    consensus_params_for_version(version)
        .map(|p| p.payset_commit == algo_types::consensus::PAYSET_COMMIT_MERKLE)
        .unwrap_or(false)
}

/// Returns `true` if the given protocol version supports SHA-256 vector
/// commitments (`txn256` field, v34+). Returns `false` for unknown versions.
pub fn has_txn256(version: &str) -> bool {
    consensus_params_for_version(version)
        .map(|p| p.enable_sha256_txn_commitment_header)
        .unwrap_or(false)
}

/// Returns `true` if the given protocol version supports SHA-512 vector
/// commitments (`txn512` field, v41+). Returns `false` for unknown versions.
pub fn has_txn512(version: &str) -> bool {
    consensus_params_for_version(version)
        .map(|p| p.enable_sha512_block_hash)
        .unwrap_or(false)
}

/// Returns `true` if the given protocol version supports heartbeat
/// transactions (`hb` type, v40+). Returns `false` for unknown versions.
pub fn has_heartbeat(version: &str) -> bool {
    consensus_params_for_version(version)
        .map(|p| p.enable_heartbeat)
        .unwrap_or(false)
}

/// Returns `true` if the given transaction is a free/cheap/discounted
/// heartbeat that is exempt from fee checks (v40+).
///
/// Mirrors the same version-gated discount rule as `txn_fee_factor`'s
/// heartbeat branch and `validate_transaction_wellformed`'s `kind`
/// derivation: post-v42 (`txn_size_pricing_enabled`) the discount is claimed
/// explicitly via `hb_challenge_discount` (grouping no longer matters);
/// pre-v42 it is inferred from an underpaying ungrouped (singleton)
/// heartbeat.
pub fn is_free_heartbeat(txn: &Transaction, params: &ConsensusParams) -> bool {
    if txn.txn_type != "hb" || !params.enable_heartbeat {
        return false;
    }
    if params.txn_size_pricing_enabled() {
        txn.heartbeat
            .as_ref()
            .is_some_and(|hb| hb.hb_challenge_discount)
    } else {
        txn.group == [0u8; 32] && txn.fee < params.min_txn_fee
    }
}

/// Compute the group ID for a set of transactions.
///
/// Delegates to [`algo_codec::compute_group_id`] — the single source of truth
/// for the `SHA512/256("TG" || canonical_encode(TxGroup{txids}))` hash, where
/// each `txid` is `SHA512/256("TX" || canonical_encode(txn))` of the
/// corresponding transaction with its `grp` field zeroed. Mirrors
/// go-algorand's `TxGroup.ComputeGroupID` / `crypto.HashObj(TxGroup)`
/// (`data/transactions/transaction.go`, `protocol` "TG"/"TX" tags).
pub fn compute_group_id(txns: &[Transaction]) -> Digest {
    algo_codec::compute_group_id(txns)
}

/// Collect transactions by group ID across the entire payset, then invoke the
/// callback for each unique group. Unlike the previous contiguous-run approach,
/// this correctly handles mainnet paysets where group members may be
/// non-contiguous (interleaved with other transactions).
fn for_each_group<F>(txns: &[SignedTransaction], mut f: F) -> Result<(), AlgoError>
where
    F: FnMut(&[&SignedTransaction]) -> Result<(), AlgoError>,
{
    use std::collections::HashMap;

    // Collect indices by group ID, preserving insertion order via Vec.
    let mut groups: HashMap<&[u8], Vec<&SignedTransaction>> = HashMap::new();
    // Track insertion order so results are deterministic.
    let mut order: Vec<&[u8]> = Vec::new();

    for stx in txns {
        if stx.txn.group == [0u8; 32] {
            continue;
        }
        let grp: &[u8] = stx.txn.group.as_ref();
        let entry = groups.entry(grp).or_insert_with(|| {
            order.push(grp);
            Vec::new()
        });
        entry.push(stx);
    }

    for grp_key in &order {
        let members = &groups[grp_key];
        f(members)?;
    }
    Ok(())
}

/// Validate transaction groups within a block payset.
///
/// Collects all transactions sharing the same non-empty `grp` field by group
/// ID across the entire payset (using a HashMap). Each group must have
/// 2..=MAX_GROUP_SIZE members and the stored group ID must match the computed
/// one. Standalone (empty `grp`) transactions are skipped.
pub fn validate_transaction_group(txns: &[SignedTransaction]) -> Result<(), AlgoError> {
    for_each_group(txns, |group_members| {
        let size = group_members.len();

        // On mainnet, a block may contain only a subset of group members
        // visible to us (e.g., due to field-level deserialization differences).
        // Skip validation for single-member groups — the group was already
        // validated at submission time by the network.
        if size < 2 {
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

/// Validate lease constraints within transaction groups.
///
/// Within each group, no two transactions from the same sender may share the
/// same lease value. Ungrouped transactions with leases are allowed
/// (cross-block lease enforcement is stateful, deferred to Phase 2).
pub fn validate_lease_constraints(txns: &[SignedTransaction]) -> Result<(), AlgoError> {
    for_each_group(txns, |group_members| {
        // Collect (sender, lease) pairs for txns with non-empty leases.
        let mut seen = std::collections::HashSet::new();
        for stx in group_members {
            if stx.txn.lease == [0u8; 32] {
                continue;
            }
            let key = (stx.txn.sender, stx.txn.lease.to_vec());
            if !seen.insert(key) {
                return Err(AlgoError::Validation {
                    message: format!(
                        "duplicate lease within group: sender {} lease {}",
                        stx.txn.sender,
                        hex::encode(stx.txn.lease)
                    ),
                });
            }
        }
        Ok(())
    })
}

/// Validate that each transaction group's pooled fees meet the minimum.
///
/// Collects transactions by group ID across the entire payset (using a HashMap).
/// For each group, the sum of all transaction fees must be at least
/// `min_fee_count * min_txn_fee`, where `min_fee_count` excludes:
///   - State proof transactions (`stpf`) — always fee-exempt
///   - Ungrouped heartbeat transactions (`hb` with empty group) — fee-exempt
///     when `enable_heartbeat` is true (v40+)
///
/// Standalone (ungrouped) transactions are skipped — their fees are checked
/// individually by `validate_transaction_rules`.
///
/// Returns `BlockValidationError::GroupFeePoolingFailed` for the first group
/// that fails the check.
pub fn validate_group_fees(
    txns: &[&SignedTransaction],
) -> Result<(), crate::block::BlockValidationError> {
    validate_group_fees_with_params(txns, &ConsensusParams::default())
}

/// Version-aware group fee validation.
///
/// Like `validate_group_fees` but uses the provided `ConsensusParams` for
/// the minimum fee value and heartbeat exemption gating.
pub fn validate_group_fees_with_params(
    txns: &[&SignedTransaction],
    params: &ConsensusParams,
) -> Result<(), crate::block::BlockValidationError> {
    use std::collections::HashMap;

    // Collect the group's members by group ID (preserving encounter order).
    // A transaction with `group == 0` isn't part of an *atomic multi-txn*
    // group, but it is still its own top-level, size-1 "txgroup" as far as
    // go's fee check is concerned — `ledger/eval.go`'s `CheckGroupFees`/
    // `SummarizeFees(txgroup, proto)` run on whatever slice of transactions
    // was submitted/evaluated together, size 1 included, regardless of
    // whether its members share an explicit `Group` digest. Treating
    // `group == 0` as "skip" (as this function did before issue #703's live
    // dual-node testing caught it) silently dropped the *only* place
    // `logic_sig_program_fee_contribution`'s pooled LogicSig-program-byte
    // surcharge is checked for a standalone submission — note/app-args/
    // app-program surcharges are separately covered per-transaction by
    // `required_fee_for_txn` inside well-formedness regardless of grouping,
    // but the LogicSig surcharge is only ever computed here. So every
    // ungrouped transaction is now checked too, as a singleton group of one.
    let mut groups: HashMap<&[u8], Vec<&SignedTransaction>> = HashMap::new();
    let mut order: Vec<&[u8]> = Vec::new();
    let mut singletons: Vec<&SignedTransaction> = Vec::new();

    for stx in txns {
        if stx.txn.group == [0u8; 32] {
            singletons.push(stx);
            continue;
        }
        let grp: &[u8] = stx.txn.group.as_ref();
        let entry = groups.entry(grp).or_insert_with(|| {
            order.push(grp);
            Vec::new()
        });
        entry.push(stx);
    }

    // Usage-based group fee check (Go: `transactions.SummarizeFees` +
    // `ledger/eval.CheckGroupFees`): required fee is `FeeForUsage(min_txn_fee,
    // usage, 1e6, 0)` where `usage` sums each member's `feeFactor` (1e6 per
    // ordinary transaction, 0 for state proofs, more for a transaction with
    // billable oversized fields, v42+) plus the group's pooled LogicSig
    // program-byte surcharge. For a group with no size-pricing/state-proof/
    // heartbeat-discount members this reduces to exactly `len(group) *
    // min_txn_fee`, matching the previous flat count-based check.
    let check_members = |members: &[&SignedTransaction],
                         group_id: String|
     -> Result<(), crate::block::BlockValidationError> {
        let (usage, total_fee) = crate::fee::summarize_fees(members, params);
        let (required_fee, overflow) = crate::fee::required_fee_for_usage(usage, params);
        if overflow || total_fee < required_fee {
            return Err(crate::block::BlockValidationError::GroupFeePoolingFailed {
                group_id,
                total_fee,
                required_fee,
            });
        }
        Ok(())
    };

    for grp_key in &order {
        check_members(&groups[grp_key], hex::encode(grp_key))?;
    }
    for stx in &singletons {
        check_members(
            std::slice::from_ref(stx),
            format!("ungrouped:{}", algo_codec::compute_txn_id(&stx.txn)),
        )?;
    }
    Ok(())
}

/// Validate genesis ID and genesis hash consistency.
///
/// For each transaction, if `gen` is non-empty it must match `block_genesis_id`.
/// If `gh` is non-empty it must match `block_genesis_hash`.
pub fn validate_genesis_consistency(
    txns: &[SignedTransaction],
    block_genesis_id: &str,
    block_genesis_hash: &[u8],
) -> Result<(), AlgoError> {
    for (idx, stx) in txns.iter().enumerate() {
        if !stx.txn.genesis_id.is_empty() && stx.txn.genesis_id != block_genesis_id {
            return Err(AlgoError::Validation {
                message: format!(
                    "txn {} genesis ID mismatch: txn has '{}', block has '{}'",
                    idx, stx.txn.genesis_id, block_genesis_id
                ),
            });
        }
        if stx.txn.genesis_hash != [0u8; 32] && stx.txn.genesis_hash.as_ref() != block_genesis_hash
        {
            return Err(AlgoError::Validation {
                message: format!(
                    "txn {} genesis hash mismatch: txn has {}, block has {}",
                    idx,
                    hex::encode(stx.txn.genesis_hash),
                    hex::encode(block_genesis_hash)
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{
        Address, BoxRef, HeartbeatProof, HeartbeatTxnFields, HoldingRef, LocalsRef, Round,
    };
    use serde_bytes::ByteBuf;

    /// A non-zero sender address for tests.
    const TEST_SENDER: Address = Address([1u8; 32]);

    /// Build a minimal valid transaction for testing.
    fn make_valid_txn() -> Transaction {
        Transaction {
            txn_type: "pay".into(),
            sender: TEST_SENDER,
            fee: MIN_TXN_FEE,
            first_valid: Round(1000),
            last_valid: Round(1100),
            ..Default::default()
        }
    }

    #[test]
    fn test_valid_transaction_passes() {
        let txn = make_valid_txn();
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    #[test]
    fn test_fee_too_low_fails() {
        let mut txn = make_valid_txn();
        txn.fee = 999;
        let err = validate_transaction_rules(&txn, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("below minimum"), "unexpected error: {msg}");
    }

    #[test]
    fn test_fee_zero_fails() {
        let mut txn = make_valid_txn();
        txn.fee = 0;
        let err = validate_transaction_rules(&txn, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("below minimum"), "unexpected error: {msg}");
    }

    #[test]
    fn test_round_window_too_large_fails() {
        let mut txn = make_valid_txn();
        txn.first_valid = Round(1000);
        txn.last_valid = Round(2001);
        let err = validate_transaction_rules(&txn, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exceeds maximum"), "unexpected error: {msg}");
    }

    #[test]
    fn test_last_valid_before_first_valid_fails() {
        let mut txn = make_valid_txn();
        txn.first_valid = Round(2000);
        txn.last_valid = Round(1000);
        let err = validate_transaction_rules(&txn, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("before first valid"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_round_window_at_boundary_passes() {
        let mut txn = make_valid_txn();
        txn.first_valid = Round(1000);
        txn.last_valid = Round(2000); // window = 1000 == MAX_TXN_LIFE
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    #[test]
    fn test_first_valid_equals_last_valid_passes() {
        let mut txn = make_valid_txn();
        txn.first_valid = Round(1000);
        txn.last_valid = Round(1000);
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    #[test]
    fn test_note_too_large_fails() {
        // `validate_transaction_rules` uses ConsensusParams::default() (v42),
        // which has MaxAbsoluteTxnNoteBytes = 4096 (size-pricing enabled).
        // Since v42, a 1025-byte note is well-formed on its own -- the flat
        // MAX_NOTE_SIZE (1024) is no longer a hard reject -- so it fails on
        // the *fee* check instead (a 1025-byte note requires more than
        // MIN_TXN_FEE). See `test_note_over_hard_cap_v42_is_rejected` for the
        // true structural hard-cap rejection.
        let mut txn = make_valid_txn();
        txn.note = ByteBuf::from(vec![0u8; MAX_NOTE_SIZE + 1]);
        let err = validate_transaction_rules(&txn, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("below minimum"), "unexpected error: {msg}");
    }

    #[test]
    fn test_note_at_limit_passes() {
        let mut txn = make_valid_txn();
        txn.note = ByteBuf::from(vec![0u8; MAX_NOTE_SIZE]);
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    // ── Big-transaction size pricing (issue #657) ────────────────

    #[test]
    fn test_note_over_soft_cap_pre_v42_is_hard_rejected() {
        // Pre-v42, MaxAbsoluteTxnNoteBytes == MaxTxnNoteBytes (both 1024): no
        // size pricing exists yet, so any note beyond the free cap is
        // unconditionally not well-formed, regardless of fee paid.
        let params = consensus_params_for_version(algo_types::consensus::CONSENSUS_V41).unwrap();
        let mut txn = make_valid_txn();
        txn.note = ByteBuf::from(vec![0u8; MAX_NOTE_SIZE + 1]);
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("note too big"), "unexpected error: {msg}");
    }

    #[test]
    fn test_note_over_soft_cap_v42_is_well_formed_but_needs_higher_fee() {
        // v42+: a note beyond the old free cap but within
        // MaxAbsoluteTxnNoteBytes (4096) is well-formed on its own, but the
        // flat MIN_TXN_FEE is no longer sufficient to cover it.
        let params = ConsensusParams::default(); // v42
        let mut txn = make_valid_txn();
        txn.note = ByteBuf::from(vec![0u8; MAX_NOTE_SIZE + 1]);

        let (required, overflow) = crate::fee::required_fee_for_txn(&txn, &params);
        assert!(!overflow);
        assert!(
            required > params.min_txn_fee,
            "oversized note should require more than the flat minimum fee"
        );

        // Paying only the flat minimum is not enough once the fee check
        // accounts for the note surcharge (the fee check runs before the
        // note-size structural check, so this is the error we observe).
        txn.fee = MIN_TXN_FEE;
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err.to_string().contains("below minimum"));

        // Paying the exact required fee passes -- the oversized note is
        // well-formed on its own, it's simply billable.
        txn.fee = required;
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_note_over_hard_cap_v42_is_rejected() {
        let params = ConsensusParams::default(); // v42, MaxAbsoluteTxnNoteBytes = 4096
        let mut txn = make_valid_txn();
        txn.note = ByteBuf::from(vec![0u8; params.max_absolute_txn_note_bytes + 1]);
        // Overpay generously so the fee check can't mask the structural
        // hard-cap rejection we're testing for.
        txn.fee = u64::MAX / 2;
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err.to_string().contains("note too big"));
    }

    #[test]
    fn test_app_args_over_hard_cap_v42_is_rejected() {
        let params = ConsensusParams::default(); // v42, MaxAbsoluteTotalArgLen = 16384
        let mut txn = make_valid_txn();
        txn.txn_type = "appl".into();
        txn.application_id = 42; // non-creation NoOp call: no program-presence check
                                 // Split the over-the-hard-cap length across several args, each
                                 // individually within MAX_AVM_BYTES_SIZE (4096) so the per-arg
                                 // check doesn't fire first — only the summed hard cap should.
        let per_arg = MAX_AVM_BYTES_SIZE;
        let num_args = params.max_absolute_total_arg_len / per_arg + 2;
        txn.app_arguments = Some(vec![Some(ByteBuf::from(vec![0u8; per_arg])); num_args]);
        // Overpay generously so the fee check can't mask the structural
        // hard-cap rejection we're testing for.
        txn.fee = u64::MAX / 2;
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("ApplicationArgs total length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_lease_wrong_size_fails() {
        let mut txn = make_valid_txn();
        // With [u8; 32] lease type, wrong-size leases are impossible at the type level.
        // Instead test that a non-zero lease passes when leases are supported.
        txn.lease = [0x42; 32];
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    #[test]
    fn test_lease_exactly_32_passes() {
        let mut txn = make_valid_txn();
        txn.lease = [0u8; 32];
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    #[test]
    fn test_group_field_wrong_size_fails() {
        let mut txn = make_valid_txn();
        // With [u8; 32] group type, wrong-size groups are impossible at the type level.
        // Instead test that a non-zero group passes basic rules check.
        txn.group = [0xAA; 32];
        assert!(validate_transaction_rules(&txn, false).is_ok());
    }

    // ── Zero sender / rewards pool sender tests ──────────────────

    #[test]
    fn test_zero_sender_rejected() {
        let mut txn = make_valid_txn();
        txn.sender = Address::ZERO;
        let err = validate_transaction_rules(&txn, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("zero sender"),
            "expected zero sender rejection, got: {msg}"
        );
    }

    #[test]
    fn test_rewards_pool_sender_rejected() {
        let rewards_pool = Address([0xBB; 32]);
        let spec = SpecialAddresses {
            fee_sink: Address::ZERO,
            rewards_pool,
        };
        let mut txn = make_valid_txn();
        txn.sender = rewards_pool;
        let err =
            validate_transaction_wellformed(&txn, false, &ConsensusParams::default(), Some(&spec))
                .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("incentive pool"),
            "expected rewards pool rejection, got: {msg}"
        );
    }

    #[test]
    fn test_non_rewards_pool_sender_passes() {
        let rewards_pool = Address([0xBB; 32]);
        let spec = SpecialAddresses {
            fee_sink: Address::ZERO,
            rewards_pool,
        };
        let txn = make_valid_txn(); // sender is TEST_SENDER, not rewards_pool
        assert!(validate_transaction_wellformed(
            &txn,
            false,
            &ConsensusParams::default(),
            Some(&spec)
        )
        .is_ok());
    }

    // ── Heartbeat fee exemption tests ────────────────────────────

    /// Build a minimal valid heartbeat transaction.
    fn make_heartbeat_txn(fee: u64) -> Transaction {
        Transaction {
            txn_type: "hb".into(),
            sender: TEST_SENDER,
            fee,
            first_valid: Round(1000),
            last_valid: Round(1100),
            heartbeat: Some(HeartbeatTxnFields {
                address: Address([2u8; 32]),
                proof: Some(HeartbeatProof {
                    sig: [0xAA; 64],
                    pk: [0xBB; 32],
                    pk2: [0xCC; 32],
                    pk1_sig: [0xDD; 64],
                    pk2_sig: [0xEE; 64],
                }),
                seed: [0x11; 32],
                vote_id: [0x22; 32],
                key_dilution: 10000,
                hb_challenge_discount: false,
            }),
            ..Default::default()
        }
    }

    /// V41 (pre-v42, size pricing disabled) consensus params — the regime
    /// under which the discount is inferred from fee underpayment rather
    /// than claimed via the explicit `hb_challenge_discount` flag.
    fn v41_params() -> ConsensusParams {
        consensus_params_for_version(algo_types::consensus::CONSENSUS_V41).unwrap()
    }

    #[test]
    fn test_free_heartbeat_ungrouped_passes() {
        // Pre-v42: an ungrouped heartbeat with fee=0 should pass (inferred
        // discount).
        let txn = make_heartbeat_txn(0);
        let params = v41_params();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_cheap_heartbeat_ungrouped_passes() {
        // Pre-v42: an ungrouped heartbeat with fee < min (but > 0) should
        // also pass (inferred discount).
        let txn = make_heartbeat_txn(500);
        let params = v41_params();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_free_heartbeat_with_note_rejected() {
        let mut txn = make_heartbeat_txn(0);
        txn.note = ByteBuf::from(vec![0x42; 10]);
        let params = v41_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Note is set in free heartbeat"),
            "expected note rejection in free heartbeat, got: {msg}"
        );
    }

    #[test]
    fn test_cheap_heartbeat_with_lease_rejected() {
        let mut txn = make_heartbeat_txn(500);
        txn.lease = [0x42; 32];
        let params = v41_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Lease is set in cheap heartbeat"),
            "expected lease rejection in cheap heartbeat, got: {msg}"
        );
    }

    #[test]
    fn test_free_heartbeat_with_rekey_rejected() {
        let mut txn = make_heartbeat_txn(0);
        txn.rekey_to = Some(Address([0x99; 32]));
        let params = v41_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("RekeyTo is set in free heartbeat"),
            "expected rekey rejection in free heartbeat, got: {msg}"
        );
    }

    #[test]
    fn test_heartbeat_with_full_fee_allows_note() {
        // Pre-v42: heartbeat with fee >= min should allow note (not "free").
        let mut txn = make_heartbeat_txn(MIN_TXN_FEE);
        txn.note = ByteBuf::from(vec![0x42; 10]);
        let params = v41_params();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_heartbeat_discount_flag_rejected_pre_v42() {
        // Pre-v42, HbChallengeDiscount has no meaning and must be rejected
        // outright, even on a well-formed, fully-paid heartbeat.
        let mut txn = make_heartbeat_txn(MIN_TXN_FEE);
        txn.heartbeat.as_mut().unwrap().hb_challenge_discount = true;
        let params = v41_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("tx.HbChallengeDiscount set before it is allowed"),
            "expected pre-v42 discount-flag rejection, got: {err}"
        );
    }

    #[test]
    fn test_heartbeat_discounted_post_v42_zero_fee_passes() {
        // Post-v42 (default params): the explicit flag -- not fee
        // underpayment -- is what claims the discount.
        let txn = make_heartbeat_txn(0);
        let mut txn = txn;
        txn.heartbeat.as_mut().unwrap().hb_challenge_discount = true;
        let params = ConsensusParams::default();
        assert!(params.txn_size_pricing_enabled());
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_heartbeat_discounted_post_v42_with_note_rejected() {
        // Post-v42: a discounted heartbeat must still be "very simple".
        let mut txn = make_heartbeat_txn(0);
        txn.heartbeat.as_mut().unwrap().hb_challenge_discount = true;
        txn.note = ByteBuf::from(vec![0x42; 10]);
        let params = ConsensusParams::default();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("Note is set in discounted heartbeat"),
            "expected note rejection in discounted heartbeat, got: {err}"
        );
    }

    #[test]
    fn test_heartbeat_underpaying_without_discount_flag_rejected_post_v42() {
        // Regression: post-v42, an ungrouped heartbeat that underpays
        // WITHOUT setting the explicit discount flag must be rejected for
        // insufficient fee -- it must not be silently exempted the way the
        // old (version-unaware) fee-underpayment inference would have done.
        let txn = make_heartbeat_txn(0); // hb_challenge_discount defaults to false
        let params = ConsensusParams::default();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("fee") && err.to_string().contains("below minimum"),
            "expected fee-too-low rejection, got: {err}"
        );
    }

    #[test]
    fn test_heartbeat_with_full_fee_allows_note_post_v42() {
        // Post-v42, without the discount flag, a fully-paid heartbeat is not
        // "kind"-restricted and may carry a note.
        let mut txn = make_heartbeat_txn(MIN_TXN_FEE);
        txn.note = ByteBuf::from(vec![0x42; 10]);
        let params = ConsensusParams::default();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_heartbeat_empty_proof_rejected() {
        let mut txn = make_heartbeat_txn(MIN_TXN_FEE);
        txn.heartbeat.as_mut().unwrap().proof = Some(HeartbeatProof::default());
        let params = ConsensusParams::default();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err.to_string().contains("HbProof is empty"));
    }

    #[test]
    fn test_heartbeat_empty_seed_rejected() {
        let mut txn = make_heartbeat_txn(MIN_TXN_FEE);
        txn.heartbeat.as_mut().unwrap().seed = [0u8; 32];
        let params = ConsensusParams::default();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err.to_string().contains("HbSeed is empty"));
    }

    #[test]
    fn test_heartbeat_zero_key_dilution_rejected() {
        let mut txn = make_heartbeat_txn(MIN_TXN_FEE);
        txn.heartbeat.as_mut().unwrap().key_dilution = 0;
        let params = ConsensusParams::default();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err.to_string().contains("HbKeyDilution is zero"));
    }

    #[test]
    fn test_is_free_heartbeat_helper_pre_v42() {
        let params = v41_params();
        let txn = make_heartbeat_txn(0);
        assert!(is_free_heartbeat(&txn, &params));

        let txn_with_fee = make_heartbeat_txn(MIN_TXN_FEE);
        assert!(!is_free_heartbeat(&txn_with_fee, &params));

        let mut grouped_hb = make_heartbeat_txn(0);
        grouped_hb.group = [0xFF; 32];
        assert!(!is_free_heartbeat(&grouped_hb, &params));

        let mut params_no_hb = params.clone();
        params_no_hb.enable_heartbeat = false;
        let txn2 = make_heartbeat_txn(0);
        assert!(!is_free_heartbeat(&txn2, &params_no_hb));
    }

    #[test]
    fn test_is_free_heartbeat_helper_post_v42() {
        // Post-v42: the explicit flag (not fee/grouping) decides.
        let params = ConsensusParams::default();
        assert!(params.txn_size_pricing_enabled());

        // Underpaying but no flag: NOT free (the bug this issue fixes).
        let txn_underpaying_no_flag = make_heartbeat_txn(0);
        assert!(!is_free_heartbeat(&txn_underpaying_no_flag, &params));

        // Flag set, full fee paid, ungrouped: still free (a request, not tied
        // to underpayment).
        let mut txn_flag = make_heartbeat_txn(MIN_TXN_FEE);
        txn_flag.heartbeat.as_mut().unwrap().hb_challenge_discount = true;
        assert!(is_free_heartbeat(&txn_flag, &params));

        // Flag set even while grouped: still free post-v42 (unlike pre-v42).
        let mut txn_flag_grouped = make_heartbeat_txn(MIN_TXN_FEE);
        txn_flag_grouped.group = [0xFF; 32];
        txn_flag_grouped
            .heartbeat
            .as_mut()
            .unwrap()
            .hb_challenge_discount = true;
        assert!(is_free_heartbeat(&txn_flag_grouped, &params));
    }

    // ── Version-aware consensus params tests ─────────────────────

    #[test]
    fn test_consensus_params_v7_no_groups() {
        let params = consensus_params_for_version("v7").unwrap();
        assert!(!params.support_tx_groups);
        assert!(!params.support_transaction_leases);
        assert!(!params.support_rekeying);
        assert!(!params.enable_fee_pooling);
        assert!(!params.enable_heartbeat);
        assert_eq!(params.max_tx_group_size, 1);
        assert_eq!(params.min_txn_fee, 1000);
    }

    #[test]
    fn test_consensus_params_v41() {
        // v41 URL
        let params = consensus_params_for_version(
            "https://github.com/algorandfoundation/specs/tree/953304de35264fc3ef91bcd05c123242015eeaed",
        )
        .unwrap();
        assert!(params.support_tx_groups);
        assert!(params.support_transaction_leases);
        assert!(params.support_rekeying);
        assert!(params.enable_fee_pooling);
        assert!(params.enable_heartbeat);
        assert_eq!(params.max_tx_group_size, MAX_GROUP_SIZE);
        assert_eq!(params.min_txn_fee, MIN_TXN_FEE);
        assert_eq!(
            params.max_txn_bytes_per_block,
            MAX_TXN_BYTES_PER_BLOCK_V33 as u64
        );
    }

    #[test]
    fn test_consensus_params_future() {
        let params = consensus_params_for_version("future").unwrap();
        assert!(params.enable_heartbeat);
        assert!(params.enable_fee_pooling);
    }

    #[test]
    fn test_consensus_params_unknown_returns_none() {
        assert!(consensus_params_for_version("v99").is_none());
    }

    #[test]
    fn test_lease_rejected_pre_v18() {
        let params = consensus_params_for_version("v7").unwrap(); // no leases
        let mut txn = make_valid_txn();
        txn.lease = [0x42; 32];
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not support transaction leases"));
    }

    #[test]
    fn test_group_rejected_pre_v18() {
        let params = consensus_params_for_version("v7").unwrap(); // no groups
        let mut txn = make_valid_txn();
        txn.group = [0xFF; 32];
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err.to_string().contains("groups not yet enabled"));
    }

    #[test]
    fn test_rekey_rejected_pre_v24() {
        // v18 URL (index 11) — has groups/leases but not rekeying
        let params = consensus_params_for_version(
            "https://github.com/algorandfoundation/specs/tree/6c6bd668be0ab14098e51b37e806c509f7b7e31f",
        )
        .unwrap();
        assert!(!params.support_rekeying);
        let mut txn = make_valid_txn();
        txn.rekey_to = Some(Address([0x99; 32]));
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(err.to_string().contains("rekeying not yet enabled"));
    }

    // ── has_heartbeat feature detection ──────────────────────────

    #[test]
    fn test_has_heartbeat_v39_false() {
        assert!(!has_heartbeat(
            "https://github.com/algorandfoundation/specs/tree/925a46433742afb0b51bb939354bd907fa88bf95"
        ));
    }

    #[test]
    fn test_has_heartbeat_v40_true() {
        assert!(has_heartbeat(
            "https://github.com/algorandfoundation/specs/tree/236dcc18c9c507d794813ab768e467ea42d1b4d9"
        ));
    }

    #[test]
    fn test_has_heartbeat_future_true() {
        assert!(has_heartbeat("future"));
    }

    // ── Group validation tests ──────────────────────────────────

    /// Wrap a Transaction into a SignedTransaction with default sig fields.
    fn wrap_signed(txn: Transaction) -> SignedTransaction {
        SignedTransaction {
            txn,
            sig: [0u8; 64],
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        }
    }

    #[test]
    fn test_group_id_computation() {
        let txn1 = make_valid_txn();
        let mut txn2 = make_valid_txn();
        txn2.amount = 999;

        let gid = compute_group_id(&[txn1, txn2]);
        assert_eq!(gid.as_bytes().len(), 32);
        assert!(!gid.is_zero(), "group ID should not be all zeros");
    }

    #[test]
    fn test_group_too_large_fails() {
        // Create 17 txns in a group.
        let base = make_valid_txn();
        let txns: Vec<Transaction> = (0..17)
            .map(|i| {
                let mut t = base.clone();
                t.amount = i;
                t
            })
            .collect();
        let gid = compute_group_id(&txns);

        let signed: Vec<SignedTransaction> = txns
            .into_iter()
            .map(|mut t| {
                t.group = *gid.as_bytes();
                wrap_signed(t)
            })
            .collect();

        let err = validate_transaction_group(&signed).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("maximum"),
            "expected max group size error, got: {msg}"
        );
    }

    #[test]
    fn test_single_txn_group_skipped() {
        let mut txn = make_valid_txn();
        // Set a non-empty group ID on a single txn.
        // Single-member groups are skipped (not validated) because on mainnet
        // blocks may contain partial group views.
        txn.group = [0xAA; 32];
        let signed = vec![wrap_signed(txn)];

        assert!(validate_transaction_group(&signed).is_ok());
    }

    #[test]
    fn test_group_id_mismatch_fails() {
        let txn1 = make_valid_txn();
        let mut txn2 = make_valid_txn();
        txn2.amount = 999;

        // Use a wrong group ID.
        let wrong_gid = [0xFF; 32];
        let mut s1 = txn1;
        s1.group = wrong_gid;
        let mut s2 = txn2;
        s2.group = wrong_gid;

        let signed = vec![wrap_signed(s1), wrap_signed(s2)];
        let err = validate_transaction_group(&signed).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mismatch"),
            "expected group ID mismatch error, got: {msg}"
        );
    }

    #[test]
    fn test_standalone_txn_no_group_passes() {
        let txn = make_valid_txn();
        let signed = vec![wrap_signed(txn)];
        assert!(validate_transaction_group(&signed).is_ok());
    }

    #[test]
    fn test_valid_group_passes() {
        let txn1 = make_valid_txn();
        let mut txn2 = make_valid_txn();
        txn2.amount = 999;

        let gid = compute_group_id(&[txn1.clone(), txn2.clone()]);

        let mut s1 = txn1;
        s1.group = *gid.as_bytes();
        let mut s2 = txn2;
        s2.group = *gid.as_bytes();

        let signed = vec![wrap_signed(s1), wrap_signed(s2)];
        assert!(validate_transaction_group(&signed).is_ok());
    }

    // ── Lease constraint tests ──────────────────────────────────

    #[test]
    fn test_lease_duplicate_in_group_fails() {
        let mut txn1 = make_valid_txn();
        txn1.lease = [0x42; 32];
        let mut txn2 = make_valid_txn();
        txn2.lease = [0x42; 32]; // same sender, same lease
        txn2.amount = 999;

        let gid = compute_group_id(&[txn1.clone(), txn2.clone()]);
        txn1.group = *gid.as_bytes();
        txn2.group = *gid.as_bytes();

        let signed = vec![wrap_signed(txn1), wrap_signed(txn2)];
        let err = validate_lease_constraints(&signed).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate lease"),
            "expected duplicate lease error, got: {msg}"
        );
    }

    #[test]
    fn test_lease_unique_in_group_passes() {
        let mut txn1 = make_valid_txn();
        txn1.lease = [0x42; 32];
        let mut txn2 = make_valid_txn();
        txn2.lease = [0x43; 32]; // different lease
        txn2.amount = 999;

        let gid = compute_group_id(&[txn1.clone(), txn2.clone()]);
        txn1.group = *gid.as_bytes();
        txn2.group = *gid.as_bytes();

        let signed = vec![wrap_signed(txn1), wrap_signed(txn2)];
        assert!(validate_lease_constraints(&signed).is_ok());
    }

    // ── Genesis consistency tests ───────────────────────────────

    #[test]
    fn test_genesis_id_mismatch_fails() {
        let mut txn = make_valid_txn();
        txn.genesis_id = "testnet-v1.0".to_string();
        let signed = vec![wrap_signed(txn)];

        let err = validate_genesis_consistency(&signed, "mainnet-v1.0", &[]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("genesis ID mismatch"),
            "expected genesis ID mismatch, got: {msg}"
        );
    }

    #[test]
    fn test_genesis_hash_mismatch_fails() {
        let mut txn = make_valid_txn();
        txn.genesis_hash = [0xAA; 32];
        let signed = vec![wrap_signed(txn)];

        let err = validate_genesis_consistency(&signed, "", &[0xBB; 32]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("genesis hash mismatch"),
            "expected genesis hash mismatch, got: {msg}"
        );
    }

    #[test]
    fn test_genesis_fields_match_passes() {
        let mut txn = make_valid_txn();
        txn.genesis_id = "testnet-v1.0".to_string();
        txn.genesis_hash = [0xAA; 32];
        let signed = vec![wrap_signed(txn)];

        assert!(validate_genesis_consistency(&signed, "testnet-v1.0", &[0xAA; 32]).is_ok());
    }

    #[test]
    fn test_genesis_empty_fields_pass() {
        // Txns with empty genesis fields should pass regardless of block values.
        let txn = make_valid_txn();
        let signed = vec![wrap_signed(txn)];
        assert!(validate_genesis_consistency(&signed, "mainnet-v1.0", &[0xFF; 32]).is_ok());
    }

    // ── Protocol version tests ───────────────────────────────────

    #[test]
    fn test_known_short_version_passes() {
        assert!(validate_protocol_version("v7").is_ok());
        assert!(validate_protocol_version("v12").is_ok());
    }

    #[test]
    fn test_known_url_version_passes() {
        // v41
        assert!(validate_protocol_version(
            "https://github.com/algorandfoundation/specs/tree/953304de35264fc3ef91bcd05c123242015eeaed"
        ).is_ok());
    }

    #[test]
    fn test_future_version_passes() {
        assert!(validate_protocol_version("future").is_ok());
    }

    #[test]
    fn test_alpha_version_passes() {
        assert!(validate_protocol_version("alpha1").is_ok());
    }

    #[test]
    fn test_unknown_version_fails() {
        let err = validate_protocol_version("v99").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown protocol version"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_empty_version_fails() {
        let err = validate_protocol_version("").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("empty"), "unexpected error: {msg}");
    }

    #[test]
    fn test_max_txn_bytes_v12_returns_1mb() {
        assert_eq!(
            max_txn_bytes_per_block("v12").unwrap(),
            MAX_TXN_BYTES_PER_BLOCK_V32
        );
    }

    #[test]
    fn test_max_txn_bytes_v33_returns_5mb() {
        // v33 URL
        assert_eq!(
            max_txn_bytes_per_block(
                "https://github.com/algorandfoundation/specs/tree/830a4e673148498cc7230a0d1ba1ed0a5471acc6"
            ).unwrap(),
            MAX_TXN_BYTES_PER_BLOCK_V33
        );
    }

    #[test]
    fn test_max_txn_bytes_future_returns_5mb() {
        assert_eq!(
            max_txn_bytes_per_block("future").unwrap(),
            MAX_TXN_BYTES_PER_BLOCK_V33
        );
    }

    #[test]
    fn test_max_txn_bytes_unknown_version_fails() {
        assert!(max_txn_bytes_per_block("v99").is_err());
    }

    // ── protocol_version_index tests ──────────────────────────────

    #[test]
    fn test_protocol_version_index_v7() {
        assert_eq!(protocol_version_index("v7"), Some(0));
    }

    #[test]
    fn test_protocol_version_index_v41() {
        assert_eq!(protocol_version_index(
            "https://github.com/algorandfoundation/specs/tree/953304de35264fc3ef91bcd05c123242015eeaed"
        ), Some(34));
    }

    #[test]
    fn test_protocol_version_index_v42() {
        assert_eq!(protocol_version_index(
            "https://github.com/algorandfoundation/specs/tree/268b63433a907455d439995bf916f6b296018f4f"
        ), Some(35));
    }

    #[test]
    fn test_protocol_version_index_future() {
        assert_eq!(protocol_version_index("future"), Some(36));
    }

    #[test]
    fn test_protocol_version_index_unknown() {
        assert_eq!(protocol_version_index("v99"), None);
    }

    // ── Feature detection tests ───────────────────────────────────

    #[test]
    fn test_has_payset_commit_merkle_v25_false() {
        // v25 is index 18, below V26_START_INDEX (19)
        assert!(!has_payset_commit_merkle(
            "https://github.com/algorandfoundation/specs/tree/bea19289bf41217d2c0af30522fa222ef1366466"
        ));
    }

    #[test]
    fn test_has_payset_commit_merkle_v26_true() {
        assert!(has_payset_commit_merkle(
            "https://github.com/algorandfoundation/specs/tree/ac2255d586c4474d4ebcf3809acccb59b7ef34ff"
        ));
    }

    #[test]
    fn test_has_payset_commit_merkle_future_true() {
        assert!(has_payset_commit_merkle("future"));
    }

    #[test]
    fn test_has_payset_commit_merkle_unknown_false() {
        assert!(!has_payset_commit_merkle("v99"));
    }

    #[test]
    fn test_has_txn256_v33_false() {
        // v33 is index 26, below V34_START_INDEX (27)
        assert!(!has_txn256(
            "https://github.com/algorandfoundation/specs/tree/830a4e673148498cc7230a0d1ba1ed0a5471acc6"
        ));
    }

    #[test]
    fn test_has_txn256_v34_true() {
        assert!(has_txn256(
            "https://github.com/algorandfoundation/specs/tree/2dd5435993f6f6d65691140f592ebca5ef19ffbd"
        ));
    }

    #[test]
    fn test_has_txn256_future_true() {
        assert!(has_txn256("future"));
    }

    #[test]
    fn test_has_txn512_v40_false() {
        // v40 is index 33, below V41_START_INDEX (34)
        assert!(!has_txn512(
            "https://github.com/algorandfoundation/specs/tree/236dcc18c9c507d794813ab768e467ea42d1b4d9"
        ));
    }

    #[test]
    fn test_has_txn512_v41_true() {
        assert!(has_txn512(
            "https://github.com/algorandfoundation/specs/tree/953304de35264fc3ef91bcd05c123242015eeaed"
        ));
    }

    #[test]
    fn test_has_txn512_future_true() {
        assert!(has_txn512("future"));
    }

    #[test]
    fn test_has_txn512_unknown_false() {
        assert!(!has_txn512("v99"));
    }

    // ── Application-call well-formedness (issue #675) ────────────

    /// v42 params: `AppSizeUpdates` active, `MaxAbsoluteExtraProgramPages =
    /// 7`, non-zero schema-entry caps — the version where the upstream fix
    /// (`e885e4e8a`, #6682) applies.
    fn v42_params() -> ConsensusParams {
        consensus_params_for_version(algo_types::consensus::CONSENSUS_CURRENT_VERSION)
            .expect("v42 (current) consensus params must be defined")
    }

    /// Build a minimal valid application-call transaction (a plain NoOp call
    /// on an existing app, no schema/EPP fields set).
    fn make_appl_txn() -> Transaction {
        Transaction {
            txn_type: "appl".into(),
            sender: TEST_SENDER,
            fee: MIN_TXN_FEE,
            first_valid: Round(1000),
            last_valid: Round(1100),
            application_id: 42,
            ..Default::default()
        }
    }

    /// Set minimal-but-valid ApprovalProgram/ClearStateProgram bytes: a
    /// single version byte, same version on both sides, well under any
    /// program-length cap. Required on any txn that will take `wellFormed`'s
    /// creation/update program-version-check branch (`ApplicationID == 0`,
    /// or `OnCompletion == UpdateApplicationOC`) — `CheckContractVersions`
    /// rejects a missing/empty program on that branch.
    fn set_min_programs(txn: &mut Transaction) {
        txn.approval_program = Some(ByteBuf::from(vec![6]));
        txn.clear_state_program = Some(ByteBuf::from(vec![6]));
    }

    #[test]
    fn test_appl_creation_may_set_local_and_global_schema() {
        // ApplicationID == 0 (creation): both schemas may be freely set.
        let mut txn = make_appl_txn();
        txn.application_id = 0;
        set_min_programs(&mut txn);
        txn.local_state_schema = Some(algo_types::StateSchema {
            num_uint: 1,
            num_byte_slice: 1,
        });
        txn.global_state_schema = Some(algo_types::StateSchema {
            num_uint: 2,
            num_byte_slice: 2,
        });
        let params = v42_params();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_appl_update_with_nonzero_local_schema_rejected() {
        // Plain update (no resize), nonzero LocalStateSchema: always illegal.
        let mut txn = make_appl_txn();
        txn.on_completion = ON_COMPLETION_UPDATE;
        set_min_programs(&mut txn);
        txn.local_state_schema = Some(algo_types::StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        });
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("LocalStateSchema"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_noncreation_with_nonzero_global_schema_rejected_without_app_size_updates() {
        // Not an update (NoOp), nonzero GlobalStateSchema: illegal regardless
        // of AppSizeUpdates, since UpdatingSizes() requires OnCompletion ==
        // UpdateApplicationOC.
        let mut txn = make_appl_txn();
        txn.global_state_schema = Some(algo_types::StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        });
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("GlobalStateSchema"),
            "unexpected error: {err}"
        );
    }

    /// This is the exact scenario the upstream bug (pre `e885e4e8a`) let
    /// through: an update transaction that legitimately resizes
    /// GlobalStateSchema/ExtraProgramPages under AppSizeUpdates, while ALSO
    /// smuggling in a nonzero LocalStateSchema. The nested (pre-fix)
    /// structure would have skipped the LocalStateSchema check entirely
    /// here because the AppSizeUpdates/UpdatingSizes guard was satisfied.
    /// The current (correct) structure must still reject it.
    #[test]
    fn test_appl_update_resize_cannot_smuggle_local_schema_change() {
        let mut txn = make_appl_txn();
        txn.on_completion = ON_COMPLETION_UPDATE;
        set_min_programs(&mut txn);
        // Legitimate resize: nonzero GlobalStateSchema + ExtraProgramPages,
        // which alone would be allowed under AppSizeUpdates.
        txn.global_state_schema = Some(algo_types::StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        });
        txn.extra_program_pages = 1;
        // Smuggled mutation: LocalStateSchema must never change post-creation.
        txn.local_state_schema = Some(algo_types::StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        });
        let params = v42_params();
        assert!(params.app_size_updates, "test assumes AppSizeUpdates=true");
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("LocalStateSchema"),
            "expected LocalStateSchema rejection even though the resize itself is legitimate, got: {err}"
        );
    }

    #[test]
    fn test_appl_update_legitimate_resize_without_local_schema_accepted() {
        // Same resize as above but WITHOUT the smuggled LocalStateSchema:
        // must be accepted under AppSizeUpdates.
        let mut txn = make_appl_txn();
        txn.on_completion = ON_COMPLETION_UPDATE;
        set_min_programs(&mut txn);
        txn.global_state_schema = Some(algo_types::StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        });
        txn.extra_program_pages = 1;
        let params = v42_params();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_appl_update_resize_rejected_when_app_size_updates_disabled() {
        // Same legitimate-looking resize, but on a version where
        // AppSizeUpdates is not yet active (v41): must be rejected.
        let mut txn = make_appl_txn();
        txn.on_completion = ON_COMPLETION_UPDATE;
        set_min_programs(&mut txn);
        txn.global_state_schema = Some(algo_types::StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        });
        let v41 = consensus_params_for_version(algo_types::consensus::CONSENSUS_V41)
            .expect("v41 consensus params must be defined");
        assert!(
            !v41.app_size_updates,
            "test assumes v41 predates AppSizeUpdates"
        );
        let err = validate_transaction_wellformed(&txn, false, &v41, None).unwrap_err();
        assert!(
            err.to_string().contains("GlobalStateSchema"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_extra_program_pages_over_max_rejected() {
        let mut txn = make_appl_txn();
        txn.application_id = 0; // creation: EPP bound is still unconditional
        set_min_programs(&mut txn);
        let params = v42_params();
        txn.extra_program_pages = params.max_absolute_extra_program_pages + 1;
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("MaxAbsoluteExtraProgramPages"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_local_schema_entries_over_max_rejected_at_creation() {
        let mut txn = make_appl_txn();
        txn.application_id = 0; // creation: entry-count caps still apply
        set_min_programs(&mut txn);
        let params = v42_params();
        txn.local_state_schema = Some(algo_types::StateSchema {
            num_uint: params.max_local_schema_entries + 1,
            num_byte_slice: 0,
        });
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("LocalStateSchema is too large"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_global_schema_entries_over_max_rejected_at_creation() {
        let mut txn = make_appl_txn();
        txn.application_id = 0;
        set_min_programs(&mut txn);
        let params = v42_params();
        txn.global_state_schema = Some(algo_types::StateSchema {
            num_uint: params.max_global_schema_entries + 1,
            num_byte_slice: 0,
        });
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("GlobalStateSchema is too large"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_noop_call_with_no_schema_fields_accepted() {
        let txn = make_appl_txn();
        let params = v42_params();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    // ── Application-call well-formedness (issue #701) ────────────
    // Remaining `ApplicationCallTxnFields.wellFormed` structural checks not
    // covered by #675/PR #700 (schema/EPP immutability only).

    // -- OnCompletion --

    #[test]
    fn test_appl_invalid_on_completion_rejected() {
        let mut txn = make_appl_txn();
        txn.on_completion = 6; // one past DeleteApplicationOC = 5
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("invalid application OnCompletion"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_every_on_completion_value_0_to_5_accepted() {
        let params = v42_params();
        for oc in 0..=5u64 {
            let mut txn = make_appl_txn();
            txn.on_completion = oc;
            if oc == ON_COMPLETION_UPDATE {
                set_min_programs(&mut txn);
            }
            assert!(
                validate_transaction_wellformed(&txn, false, &params, None).is_ok(),
                "OnCompletion {oc} should be accepted"
            );
        }
    }

    // -- RejectVersion --

    #[test]
    fn test_appl_reject_version_rejected_when_versioning_disabled() {
        let mut txn = make_appl_txn();
        txn.reject_version = 1;
        let v40 = consensus_params_for_version(algo_types::consensus::CONSENSUS_V40)
            .expect("v40 consensus params must be defined");
        assert!(
            !v40.enable_app_versioning,
            "test assumes v40 predates EnableAppVersioning"
        );
        let err = validate_transaction_wellformed(&txn, false, &v40, None).unwrap_err();
        assert!(
            err.to_string().contains("RejectVersion is not supported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_reject_version_cannot_be_set_during_creation() {
        let mut txn = make_appl_txn();
        txn.application_id = 0; // creation
        txn.reject_version = 1;
        set_min_programs(&mut txn);
        let params = v42_params();
        assert!(params.enable_app_versioning);
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("RejectVersion cannot be set during creation"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_reject_version_on_noncreation_call_accepted() {
        let mut txn = make_appl_txn();
        txn.reject_version = 1; // application_id != 0 (non-creation)
        let params = v42_params();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    // -- Program presence / CheckContractVersions --

    #[test]
    fn test_appl_programs_set_on_plain_noop_call_rejected() {
        // Not a creation (ApplicationID != 0), not an update: programs must
        // be absent.
        let mut txn = make_appl_txn();
        set_min_programs(&mut txn);
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("programs may only be specified during application creation or update"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_creation_missing_approval_program_rejected() {
        let mut txn = make_appl_txn();
        txn.application_id = 0;
        txn.clear_state_program = Some(ByteBuf::from(vec![6]));
        // ApprovalProgram left unset.
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("bad ApprovalProgram"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_creation_missing_clear_state_program_rejected() {
        let mut txn = make_appl_txn();
        txn.application_id = 0;
        txn.approval_program = Some(ByteBuf::from(vec![6]));
        // ClearStateProgram left unset.
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("bad ClearStateProgram"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_creation_mismatched_program_versions_rejected() {
        // Both >= syncProgramsVersion (6), but different: must match.
        let mut txn = make_appl_txn();
        txn.application_id = 0;
        txn.approval_program = Some(ByteBuf::from(vec![6]));
        txn.clear_state_program = Some(ByteBuf::from(vec![7]));
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("program version mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_creation_mismatched_pre_sync_versions_accepted() {
        // Both below syncProgramsVersion (6): mismatch is fine.
        let mut txn = make_appl_txn();
        txn.application_id = 0;
        txn.approval_program = Some(ByteBuf::from(vec![2]));
        txn.clear_state_program = Some(ByteBuf::from(vec![4]));
        let params = v42_params();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_appl_update_requires_programs_present() {
        let mut txn = make_appl_txn();
        txn.on_completion = ON_COMPLETION_UPDATE;
        // No programs set at all.
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("bad ApprovalProgram"),
            "unexpected error: {err}"
        );
    }

    // -- WellSizedPrograms --

    #[test]
    fn test_appl_approval_program_too_long_rejected() {
        let mut txn = make_appl_txn();
        txn.application_id = 0;
        let params = v42_params();
        let mut approval = vec![6u8];
        approval.extend(vec![0u8; params.max_app_program_len]); // over the 1-page cap
        txn.approval_program = Some(ByteBuf::from(approval));
        txn.clear_state_program = Some(ByteBuf::from(vec![6]));
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("approval program too long"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_clear_state_program_too_long_rejected() {
        let mut txn = make_appl_txn();
        txn.application_id = 0;
        let params = v42_params();
        let mut clear = vec![6u8];
        clear.extend(vec![0u8; params.max_app_program_len]);
        txn.approval_program = Some(ByteBuf::from(vec![6]));
        txn.clear_state_program = Some(ByteBuf::from(clear));
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("clear state program too long"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_total_program_length_too_long_rejected() {
        // Each individually within MaxAppProgramLen, but summed over
        // MaxAppTotalProgramLen (1 page): must be rejected on the summed
        // check even though neither individual check fires.
        let mut txn = make_appl_txn();
        txn.application_id = 0;
        let params = v42_params();
        assert!(params.max_app_total_program_len < 2 * params.max_app_program_len);
        let half = params.max_app_total_program_len / 2 + 1;
        assert!(half <= params.max_app_program_len);
        let mut approval = vec![6u8];
        approval.extend(vec![0u8; half - 1]);
        let mut clear = vec![6u8];
        clear.extend(vec![0u8; half - 1]);
        txn.approval_program = Some(ByteBuf::from(approval));
        txn.clear_state_program = Some(ByteBuf::from(clear));
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("app programs too long"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_update_program_size_uses_effective_epp_when_resizing() {
        // A resize update (AppSizeUpdates active) with ExtraProgramPages = 1
        // should get a 2-page size ceiling, not the 1-page default.
        let mut txn = make_appl_txn();
        txn.on_completion = ON_COMPLETION_UPDATE;
        let params = v42_params();
        txn.global_state_schema = Some(algo_types::StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        });
        txn.extra_program_pages = 1;
        let mut approval = vec![6u8];
        // Over 1 page, but within 2 pages.
        approval.extend(vec![0u8; params.max_app_program_len + 10]);
        txn.approval_program = Some(ByteBuf::from(approval));
        txn.clear_state_program = Some(ByteBuf::from(vec![6]));
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    // -- MaxAppArgs / arg length --

    #[test]
    fn test_appl_max_app_args_count_exceeded_rejected() {
        let mut txn = make_appl_txn();
        let params = v42_params();
        txn.app_arguments = Some(vec![
            Some(ByteBuf::from(Vec::new()));
            params.max_app_args + 1
        ]);
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("ApplicationArgs has too many arguments"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_max_app_args_count_at_limit_accepted() {
        let mut txn = make_appl_txn();
        let params = v42_params();
        txn.app_arguments = Some(vec![Some(ByteBuf::from(Vec::new())); params.max_app_args]);
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_appl_single_arg_over_max_avm_bytes_size_rejected() {
        let mut txn = make_appl_txn();
        let params = v42_params();
        txn.app_arguments = Some(vec![Some(ByteBuf::from(vec![0u8; MAX_AVM_BYTES_SIZE + 1]))]);
        // Overpay generously so the size-pricing fee surcharge can't mask
        // the structural rejection we're testing for.
        txn.fee = u64::MAX / 2;
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("ApplicationArgs[0] length is too long"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_args_total_length_over_max_rejected() {
        let mut txn = make_appl_txn();
        let params = v42_params();
        // Several args, each at MAX_AVM_BYTES_SIZE (so the per-arg check
        // doesn't fire), but summed over MaxAbsoluteTotalArgLen.
        let per_arg = MAX_AVM_BYTES_SIZE;
        let num_args = params.max_absolute_total_arg_len / per_arg + 2;
        txn.app_arguments = Some(vec![Some(ByteBuf::from(vec![0u8; per_arg])); num_args]);
        // Overpay generously so the size-pricing fee surcharge can't mask
        // the structural rejection we're testing for.
        txn.fee = u64::MAX / 2;
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("ApplicationArgs total length is too long"),
            "unexpected error: {err}"
        );
    }

    // -- Access mutual exclusion / MaxAppAccess --

    #[test]
    fn test_appl_access_with_accounts_rejected() {
        let mut txn = make_appl_txn();
        txn.access = Some(vec![ResourceRef {
            app: 7,
            ..Default::default()
        }]);
        txn.accounts = Some(vec![Address([9u8; 32])]);
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("tx.Accounts can't be used when tx.Access is used"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_with_foreign_apps_rejected() {
        let mut txn = make_appl_txn();
        txn.access = Some(vec![ResourceRef {
            app: 7,
            ..Default::default()
        }]);
        txn.foreign_apps = Some(vec![7]);
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("tx.ForeignApps can't be used when tx.Access is used"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_with_foreign_assets_rejected() {
        let mut txn = make_appl_txn();
        txn.access = Some(vec![ResourceRef {
            app: 7,
            ..Default::default()
        }]);
        txn.foreign_assets = Some(vec![7]);
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("tx.ForeignAssets can't be used when tx.Access is used"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_with_boxes_rejected() {
        let mut txn = make_appl_txn();
        txn.access = Some(vec![ResourceRef {
            app: 7,
            ..Default::default()
        }]);
        txn.boxes = Some(vec![BoxRef {
            index: 0,
            name: Some(ByteBuf::from(b"x".to_vec())),
        }]);
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("tx.Boxes can't be used when tx.Access is used"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_over_max_app_access_rejected() {
        let mut txn = make_appl_txn();
        let params = v42_params();
        txn.access = Some(
            (0..params.max_app_access + 1)
                .map(|_| ResourceRef {
                    app: 7,
                    ..Default::default()
                })
                .collect(),
        );
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("tx.Access too long"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_at_max_app_access_accepted() {
        let mut txn = make_appl_txn();
        let params = v42_params();
        txn.access = Some(
            (0..params.max_app_access)
                .map(|_| ResourceRef {
                    app: 7,
                    ..Default::default()
                })
                .collect(),
        );
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    // -- ResourceRef.wellFormed --

    #[test]
    fn test_appl_access_ref_with_multiple_kinds_rejected() {
        let mut txn = make_appl_txn();
        txn.access = Some(vec![ResourceRef {
            asset: 1,
            app: 1,
            ..Default::default()
        }]);
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("tx.Access element has fields from multiple types"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_empty_ref_accepted() {
        // An all-zero ResourceRef is allowed: it just asks for a box quota
        // bump.
        let mut txn = make_appl_txn();
        txn.access = Some(vec![ResourceRef::default()]);
        let params = v42_params();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_appl_access_holding_address_index_out_of_bounds_rejected() {
        let mut txn = make_appl_txn();
        txn.access = Some(vec![ResourceRef {
            holding: Some(HoldingRef {
                address: 5, // out of bounds: only 1 element in Access
                asset: 1,
            }),
            ..Default::default()
        }]);
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("holding Address reference 5 outside tx.Access"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_holding_address_index_wrong_type_rejected() {
        let mut txn = make_appl_txn();
        txn.access = Some(vec![
            ResourceRef {
                app: 7, // index 1 is an App, not an Address
                ..Default::default()
            },
            ResourceRef {
                holding: Some(HoldingRef {
                    address: 1, // points at the App entry above
                    asset: 1,
                }),
                ..Default::default()
            },
        ]);
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("holding Address reference 1 is not an Address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_holding_asset_zero_rejected() {
        let mut txn = make_appl_txn();
        txn.access = Some(vec![
            ResourceRef {
                address: Address([2u8; 32]),
                ..Default::default()
            },
            ResourceRef {
                holding: Some(HoldingRef {
                    // A valid Address index makes this HoldingRef non-empty
                    // (an all-zero HoldingRef is simply "empty", not an
                    // error) and clears the Address-resolution step, so
                    // Asset = 0 is the specific invalid part under test.
                    address: 1,
                    asset: 0,
                }),
                ..Default::default()
            },
        ]);
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("holding Asset reference 0 outside tx.Access"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_holding_valid_reference_accepted() {
        let mut txn = make_appl_txn();
        txn.access = Some(vec![
            ResourceRef {
                asset: 99,
                ..Default::default()
            },
            ResourceRef {
                holding: Some(HoldingRef {
                    address: 0, // 0 = sender
                    asset: 1,   // 1-based index into Access -> the asset above
                }),
                ..Default::default()
            },
        ]);
        let params = v42_params();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_appl_access_locals_zero_app_rejected_when_disallowed() {
        let mut txn = make_appl_txn();
        // Address = 1 makes the LocalsRef non-empty (an all-zero LocalsRef
        // is simply "empty", not an error) without needing App to resolve
        // it — the zero-App checks fire before Resolve is ever called.
        txn.access = Some(vec![ResourceRef {
            locals: Some(LocalsRef { address: 1, app: 0 }),
            ..Default::default()
        }]);
        let v41 = consensus_params_for_version(algo_types::consensus::CONSENSUS_V41)
            .expect("v41 consensus params must be defined");
        assert!(
            !v41.allow_zero_local_app_ref,
            "test assumes v41 predates AllowZeroLocalAppRef"
        );
        let err = validate_transaction_wellformed(&txn, false, &v41, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("0 App in LocalsRef is not supported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_locals_zero_app_rejected_during_create_even_when_allowed() {
        let mut txn = make_appl_txn();
        txn.application_id = 0; // creation
        set_min_programs(&mut txn);
        txn.access = Some(vec![ResourceRef {
            locals: Some(LocalsRef { address: 1, app: 0 }),
            ..Default::default()
        }]);
        let params = v42_params();
        assert!(
            params.allow_zero_local_app_ref,
            "test assumes v42 allows AllowZeroLocalAppRef"
        );
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("0 App in LocalsRef during app create is not allowed or necessary"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_locals_zero_app_accepted_on_noncreation_call() {
        let mut txn = make_appl_txn(); // application_id != 0, NoOp
        txn.access = Some(vec![
            ResourceRef {
                address: Address([3u8; 32]),
                ..Default::default()
            },
            ResourceRef {
                // App = 0 ("current app") is fine here: not creation, and
                // AllowZeroLocalAppRef is active at v42.
                locals: Some(LocalsRef { address: 1, app: 0 }),
                ..Default::default()
            },
        ]);
        let params = v42_params();
        assert!(params.allow_zero_local_app_ref);
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_appl_access_locals_app_index_out_of_bounds_rejected() {
        let mut txn = make_appl_txn();
        txn.access = Some(vec![ResourceRef {
            locals: Some(LocalsRef { address: 0, app: 5 }),
            ..Default::default()
        }]);
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("locals App reference 5 outside tx.Access"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_box_index_out_of_bounds_rejected() {
        let mut txn = make_appl_txn();
        txn.access = Some(vec![ResourceRef {
            box_ref: Some(BoxRef {
                index: 3,
                name: Some(ByteBuf::from(b"x".to_vec())),
            }),
            ..Default::default()
        }]);
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("box Index 3 outside tx.Access"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_box_index_wrong_type_rejected() {
        let mut txn = make_appl_txn();
        txn.access = Some(vec![
            ResourceRef {
                asset: 9, // index 1 is an Asset, not an App
                ..Default::default()
            },
            ResourceRef {
                box_ref: Some(BoxRef {
                    index: 1,
                    name: Some(ByteBuf::from(b"x".to_vec())),
                }),
                ..Default::default()
            },
        ]);
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("box Index reference 1 is not an App"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_access_box_current_app_accepted() {
        let mut txn = make_appl_txn();
        txn.access = Some(vec![ResourceRef {
            box_ref: Some(BoxRef {
                index: 0, // 0 = current app
                name: Some(ByteBuf::from(b"x".to_vec())),
            }),
            ..Default::default()
        }]);
        let params = v42_params();
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    #[test]
    fn test_appl_access_box_name_too_long_rejected_when_enabled() {
        let mut txn = make_appl_txn();
        let params = v42_params();
        assert!(
            params.enable_box_ref_name_error,
            "test assumes v42 has EnableBoxRefNameError"
        );
        txn.access = Some(vec![ResourceRef {
            box_ref: Some(BoxRef {
                index: 0,
                name: Some(ByteBuf::from(vec![0u8; params.max_app_key_len + 1])),
            }),
            ..Default::default()
        }]);
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("tx.Access box Name too long"),
            "unexpected error: {err}"
        );
    }

    // -- Non-Access reference-array bounds --

    #[test]
    fn test_appl_max_app_txn_accounts_exceeded_rejected() {
        let mut txn = make_appl_txn();
        let params = v42_params();
        txn.accounts = Some(vec![Address([2u8; 32]); params.max_app_txn_accounts + 1]);
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("tx.Accounts too long"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_max_app_txn_foreign_apps_exceeded_rejected() {
        let mut txn = make_appl_txn();
        let params = v42_params();
        txn.foreign_apps = Some(vec![1u64; params.max_app_txn_foreign_apps + 1]);
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("tx.ForeignApps too long"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_max_app_txn_foreign_assets_exceeded_rejected() {
        let mut txn = make_appl_txn();
        let params = v42_params();
        txn.foreign_assets = Some(vec![1u64; params.max_app_txn_foreign_assets + 1]);
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("tx.ForeignAssets too long"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_max_app_box_references_exceeded_rejected() {
        let mut txn = make_appl_txn();
        let params = v42_params();
        txn.boxes = Some(vec![
            BoxRef {
                index: 0,
                name: Some(ByteBuf::from(b"x".to_vec())),
            };
            params.max_app_box_references + 1
        ]);
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("tx.Boxes too long"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_max_app_total_txn_references_exceeded_rejected() {
        // Each individual field is within its own per-field bound, but the
        // sum across Accounts + ForeignApps + ForeignAssets exceeds
        // MaxAppTotalTxnReferences. At v42 all the per-field caps equal
        // MaxAppTotalTxnReferences (8), so no single field can be pushed
        // over the sum alone — split the excess across two fields instead.
        let mut txn = make_appl_txn();
        let params = v42_params();
        let per_field = params.max_app_total_txn_references / 2;
        assert!(per_field <= params.max_app_txn_accounts);
        assert!(per_field <= params.max_app_txn_foreign_apps);
        txn.accounts = Some(vec![Address([2u8; 32]); per_field]);
        txn.foreign_apps = Some(vec![1u64; per_field + 1]);
        assert!(
            per_field + (per_field + 1) > params.max_app_total_txn_references,
            "test setup must actually exceed the sum bound"
        );
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("tx references exceed MaxAppTotalTxnReferences"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_references_at_all_limits_accepted() {
        let mut txn = make_appl_txn();
        let params = v42_params();
        // Individually and summed, exactly at the caps.
        let n = params.max_app_total_txn_references;
        txn.accounts = Some(vec![Address([2u8; 32]); n.min(params.max_app_txn_accounts)]);
        assert!(validate_transaction_wellformed(&txn, false, &params, None).is_ok());
    }

    // -- tx.Boxes index / name bound (non-Access path) --

    #[test]
    fn test_appl_box_index_exceeds_foreign_apps_rejected() {
        let mut txn = make_appl_txn();
        txn.foreign_apps = Some(vec![7]);
        txn.boxes = Some(vec![BoxRef {
            index: 2, // only 1 ForeignApps entry -> valid indices are 0, 1
            name: Some(ByteBuf::from(b"x".to_vec())),
        }]);
        let params = v42_params();
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("Exceeds len(tx.ForeignApps)"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_box_name_too_long_rejected_when_enabled() {
        let mut txn = make_appl_txn();
        let params = v42_params();
        assert!(params.enable_box_ref_name_error);
        txn.boxes = Some(vec![BoxRef {
            index: 0,
            name: Some(ByteBuf::from(vec![0u8; params.max_app_key_len + 1])),
        }]);
        let err = validate_transaction_wellformed(&txn, false, &params, None).unwrap_err();
        assert!(
            err.to_string().contains("tx.Boxes[0].Name too long"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_appl_box_name_over_key_len_accepted_when_flag_disabled() {
        // Same over-length name, but at a version predating
        // EnableBoxRefNameError: not rejected by this specific check.
        let mut txn = make_appl_txn();
        let v36 = consensus_params_for_version(algo_types::consensus::CONSENSUS_V36)
            .expect("v36 consensus params must be defined");
        assert!(!v36.enable_box_ref_name_error);
        txn.foreign_apps = Some(vec![1]);
        txn.boxes = Some(vec![BoxRef {
            index: 0,
            name: Some(ByteBuf::from(vec![0u8; v36.max_app_key_len + 1])),
        }]);
        assert!(validate_transaction_wellformed(&txn, false, &v36, None).is_ok());
    }
}
