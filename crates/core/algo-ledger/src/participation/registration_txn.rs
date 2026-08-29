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

//! Build a keyreg `Transaction` from a `Participation`.
//!
//! Rust port of go-algorand's
//! `Participation::GenerateRegistrationTransaction` at
//! `../go-algorand/data/account/participation.go:159-183`.
//! Consumed by `algokey keyreg --keyfile <partkey>` (TASK-170).
//!
//! The returned `Transaction` has GenesisHash zeroed; the caller is
//! expected to fill it via `algo_types::resolve_genesis_hash`
//! (TASK-163) — mirrors Go's flow at
//! `cmd/algokey/keyreg.go:228-232`.

use algo_types::{Round, Transaction, TxnType};

use crate::participation::Participation;

/// Build an unsigned `KeyRegistrationTx` from the participation key.
///
/// Fields populated:
/// - `Type = Keyreg`
/// - `sender = part.parent`
/// - `fee`, `first_valid`, `last_valid`, `lease` — from arguments
/// - `vote_pk` = `part.voting.verifier()`
/// - `selection_pk` = `part.vrf.pk`
/// - `vote_first` = `part.first_valid`
/// - `vote_last` = `part.last_valid`
/// - `vote_key_dilution` = `part.key_dilution`
/// - `state_proof_pk` = first 64 bytes of the state-proof commitment
///   IFF `include_state_proof_key` AND `part.state_proof_secrets.is_some()`
///
/// `non_participation` is always `false` for an online registration;
/// the offline form lives in `algokey keyreg --offline` (TASK-170)
/// which constructs the txn inline without this builder.
///
/// `genesis_hash` is left zeroed — TASK-170 fills it via
/// `resolve_genesis_hash(network)`.
pub fn generate_registration_transaction(
    part: &Participation,
    fee: u64,
    first_valid: Round,
    last_valid: Round,
    lease: [u8; 32],
    include_state_proof_key: bool,
) -> Transaction {
    let vote_pk = part.voting.verifier();
    let selection_pk = part.vrf.pk.0;

    // Go's `state_proof_pk` is the merklesignature.Commitment (64 bytes).
    // Populate only when the partkey actually carries state-proof
    // secrets AND the caller requested it (matches part.go:174-178).
    let state_proof_pk: Option<[u8; 64]> = if include_state_proof_key {
        part.state_proof_secrets
            .as_ref()
            .map(|secrets| secrets.get_verifier().commitment)
    } else {
        None
    };

    Transaction {
        txn_type: TxnType::Keyreg,
        sender: part.parent,
        fee,
        first_valid,
        last_valid,
        lease,
        vote_pk: Some(vote_pk),
        selection_pk: Some(selection_pk),
        state_proof_pk,
        vote_first: part.first_valid.0,
        vote_last: part.last_valid.0,
        vote_key_dilution: part.key_dilution,
        non_participation: false,
        ..Transaction::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::erasable_db::ErasableDb;
    use crate::participation::restore_participation;
    use std::path::PathBuf;

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/partkey/small.sqlite")
    }

    /// Build a keyreg txn from the committed partkey fixture and assert
    /// every consensus-relevant field matches what Go would populate.
    /// Expected values are pinned from `algokey part info` output (see
    /// tests/partkey_reader_test.rs).
    #[test]
    fn builds_keyreg_txn_with_go_compatible_fields() {
        let db = ErasableDb::open_read_only(fixture_path()).expect("open partkey");
        let part = restore_participation(&db).expect("restore");
        let txn = generate_registration_transaction(
            &part,
            1000,
            Round(50),
            Round(150),
            [0u8; 32],
            /*include_state_proof_key=*/ true,
        );

        assert_eq!(txn.txn_type, TxnType::Keyreg);
        assert_eq!(
            txn.sender.to_string(),
            "HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI"
        );
        assert_eq!(txn.fee, 1000);
        assert_eq!(txn.first_valid.0, 50);
        assert_eq!(txn.last_valid.0, 150);
        assert_eq!(txn.lease, [0u8; 32]);

        // Selection PK = VRF PK = Go's b64 ZZGfkAW3...
        use data_encoding::BASE64;
        let want_sel = BASE64
            .decode(b"ZZGfkAW3Aez9he8NSXK3VG99y05mZmK8RoJ8WQ+zd+k=")
            .unwrap();
        assert_eq!(txn.selection_pk.expect("selection_pk").to_vec(), want_sel);

        // Vote PK = OTS verifier = Go's b64 ygCFE+...
        let want_vote = BASE64
            .decode(b"ygCFE+BjxNTnl2l3gLbbl4SBqp1Cqkc5dBZoUf9nPmI=")
            .unwrap();
        assert_eq!(txn.vote_pk.expect("vote_pk").to_vec(), want_vote);

        // state_proof_pk: include flag on AND secrets present → must be
        // the merkle commitment (64 bytes, b64 waNZ0zpeKHIPc...).
        let want_sp = BASE64
            .decode(b"waNZ0zpeKHIPcReils6xnVxYKPmMYXQ9Q8XMf5udh2MZUCmxT4DuS6zejH0IKksMiyZgXfyKv6BhPWZsWZ1/Ag==")
            .unwrap();
        assert_eq!(
            txn.state_proof_pk.expect("state_proof_pk").to_vec(),
            want_sp,
            "state_proof_pk diverges from Go's algokey part info output"
        );

        // Vote rounds + dilution = partkey's own first/last/dilution.
        assert_eq!(txn.vote_first, 1);
        assert_eq!(txn.vote_last, 100);
        assert_eq!(txn.vote_key_dilution, 10);

        // Non-participation always false for online registration.
        assert!(!txn.non_participation);

        // GenesisHash is left zeroed — caller (TASK-170) fills it.
        assert_eq!(txn.genesis_hash, [0u8; 32]);
    }

    /// `include_state_proof_key=false` zeros the `state_proof_pk`
    /// even when the partkey carries secrets — mirrors Go's
    /// `if includeStateProofKeys { ... }` guard at part.go:175.
    #[test]
    fn include_state_proof_key_false_zeros_field() {
        let db = ErasableDb::open_read_only(fixture_path()).unwrap();
        let part = restore_participation(&db).unwrap();
        let txn =
            generate_registration_transaction(&part, 1000, Round(50), Round(150), [0u8; 32], false);
        assert!(
            txn.state_proof_pk.is_none() || txn.state_proof_pk == Some([0u8; 64]),
            "state_proof_pk should be absent when include flag is false"
        );
    }

    /// Lease bytes propagate verbatim to the header.
    #[test]
    fn lease_bytes_passthrough() {
        let db = ErasableDb::open_read_only(fixture_path()).unwrap();
        let part = restore_participation(&db).unwrap();
        let mut lease = [0u8; 32];
        for (i, b) in lease.iter_mut().enumerate() {
            *b = i as u8;
        }
        let txn = generate_registration_transaction(&part, 1000, Round(1), Round(10), lease, true);
        assert_eq!(txn.lease, lease);
    }
}
