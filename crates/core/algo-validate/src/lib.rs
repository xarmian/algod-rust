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

pub mod block;
pub mod checks;
pub mod fee;
pub mod merkle;
pub mod rules;
pub mod signature;
pub mod verified_txn_cache;

pub use block::{
    contents_match_header, validate_block, BlockValidationError, BlockValidationResult,
};
pub use checks::{check_payset, check_txn_group};
pub use fee::{
    app_call_fee_contribution, effective_max_note_bytes, effective_max_total_arg_len,
    fee_for_usage, header_fee_contribution, large_program_extra_bytes,
    logic_sig_program_fee_contribution, micros_mul_int, required_fee_for_txn,
    required_fee_for_usage, signature_fee_contribution, summarize_fees, txn_fee_factor,
    FEE_RESIDUE_SCALE, ONE_MICROS,
};
pub use rules::{
    compute_group_id, consensus_params_for_version, has_heartbeat, is_free_heartbeat,
    max_txn_bytes_per_block, validate_genesis_consistency, validate_group_fees,
    validate_group_fees_with_params, validate_lease_constraints, validate_protocol_version,
    validate_transaction_group, validate_transaction_group_strict, validate_transaction_rules,
    validate_transaction_wellformed, ConsensusParams, SpecialAddresses, KNOWN_PROTOCOL_VERSIONS,
    MAX_GROUP_SIZE, MAX_LEASE_SIZE, MAX_NOTE_SIZE, MAX_TIMESTAMP_INCREMENT,
    MAX_TXN_BYTES_PER_BLOCK_V32, MAX_TXN_BYTES_PER_BLOCK_V33, MAX_TXN_LIFE, MIN_TXN_FEE,
};
pub use signature::{
    hash_program, logic_sig_group_size_check, logicsig_sanity_check, validate_pqsig_envelope,
    validate_pqsig_scheme, verify_auth_addr_sender_diff, verify_group_logicsig_size,
    verify_heartbeat_proof, verify_single_sig, verify_transaction_signature,
    verify_transaction_signature_with_tracer,
};
pub use verified_txn_cache::{
    GroupContext, VerificationContext, VerifiedTransactionCache, VerifiedTxnCacheError,
};
