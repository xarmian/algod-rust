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

//! go `bookkeeping.BlockHeader.Alive` (`data/bookkeeping/block.go`): whether
//! a transaction may appear in a block, which `BlockEvaluator.transaction`
//! checks first under `Validate: true` (block proposal, the pool's pending
//! block, simulate).

use algo_types::consensus::ConsensusParams;
use algo_types::{Digest, Transaction};

/// go `bookkeeping.TxnDeadError.Error()`: `txn dead: round R outside of F--L`,
/// the same text for a not-yet-valid and an expired transaction (the pool
/// tells them apart by comparing R with F).
pub fn txn_dead_message(round: u64, first_valid: u64, last_valid: u64) -> String {
    format!("txn dead: round {round} outside of {first_valid}--{last_valid}")
}

/// go `BlockHeader.Alive(tx)` for the block at `round` with the given genesis
/// identity, under that block's protocol `params`. `Err` carries go's error
/// text verbatim:
/// - the validity window ([`txn_dead_message`]);
/// - a non-empty genesis ID that differs from the block's;
/// - with `SupportGenesisHash`: a non-zero genesis hash that differs, or a
///   missing one under `RequireGenesisHash`;
/// - without it: any genesis hash at all.
pub fn block_alive(
    round: u64,
    genesis_id: &str,
    genesis_hash: &[u8; 32],
    params: &ConsensusParams,
    txn: &Transaction,
) -> Result<(), String> {
    block_alive_with_genesis(
        round,
        genesis_id,
        genesis_hash,
        params,
        txn,
        &txn.genesis_id,
        &txn.genesis_hash,
    )
}

/// [`block_alive`] for a transaction whose genesis id / hash are given
/// separately: a block's payset stores them stripped, and go's
/// `DecodeSignedTxn` restores them before `Alive` runs (pass
/// `GenesisRestoreRule::restored_genesis`), so no transaction is cloned.
pub fn block_alive_with_genesis(
    round: u64,
    genesis_id: &str,
    genesis_hash: &[u8; 32],
    params: &ConsensusParams,
    txn: &Transaction,
    txn_genesis_id: &str,
    txn_genesis_hash: &[u8; 32],
) -> Result<(), String> {
    let (first, last) = (txn.first_valid.0, txn.last_valid.0);
    if round < first || round > last {
        return Err(txn_dead_message(round, first, last));
    }
    if !txn_genesis_id.is_empty() && txn_genesis_id != genesis_id {
        return Err(format!(
            "tx.GenesisID <{txn_genesis_id}> does not match expected <{genesis_id}>"
        ));
    }
    let zero = [0u8; 32];
    if params.support_genesis_hash {
        if *txn_genesis_hash != zero && txn_genesis_hash != genesis_hash {
            return Err(format!(
                "tx.GenesisHash <{}> does not match expected <{}>",
                Digest(*txn_genesis_hash),
                Digest(*genesis_hash),
            ));
        }
        if params.require_genesis_hash && *txn_genesis_hash == zero {
            return Err("required tx.GenesisHash is missing".to_string());
        }
    } else if *txn_genesis_hash != zero {
        return Err(format!(
            "tx.GenesisHash <{}> not allowed",
            Digest(*txn_genesis_hash)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(support: bool, require: bool) -> ConsensusParams {
        ConsensusParams {
            support_genesis_hash: support,
            require_genesis_hash: require,
            ..Default::default()
        }
    }

    fn txn(first: u64, last: u64, gen: &str, gh: [u8; 32]) -> Transaction {
        Transaction {
            first_valid: first.into(),
            last_valid: last.into(),
            genesis_id: gen.to_string(),
            genesis_hash: gh,
            ..Default::default()
        }
    }

    #[test]
    fn window_genesis_id_and_hash_follow_go_alive() {
        let gh = [7u8; 32];
        let p = params(true, true);
        assert_eq!(
            block_alive(5, "net", &gh, &p, &txn(1, 9, "net", gh)),
            Ok(())
        );
        assert_eq!(
            block_alive(5, "net", &gh, &p, &txn(6, 9, "net", gh)),
            Err("txn dead: round 5 outside of 6--9".to_string())
        );
        assert_eq!(
            block_alive(5, "net", &gh, &p, &txn(1, 4, "net", gh)),
            Err("txn dead: round 5 outside of 1--4".to_string())
        );
        assert_eq!(
            block_alive(5, "net", &gh, &p, &txn(1, 9, "other", gh)),
            Err("tx.GenesisID <other> does not match expected <net>".to_string())
        );
        // An omitted genesis ID is accepted.
        assert_eq!(block_alive(5, "net", &gh, &p, &txn(1, 9, "", gh)), Ok(()));
        let wrong = block_alive(5, "net", &gh, &p, &txn(1, 9, "net", [8u8; 32])).unwrap_err();
        assert!(wrong.starts_with("tx.GenesisHash <") && wrong.contains("does not match expected"));
        assert_eq!(
            block_alive(5, "net", &gh, &p, &txn(1, 9, "net", [0u8; 32])),
            Err("required tx.GenesisHash is missing".to_string())
        );
        // Without RequireGenesisHash an omitted hash is accepted.
        assert_eq!(
            block_alive(
                5,
                "net",
                &gh,
                &params(true, false),
                &txn(1, 9, "net", [0u8; 32])
            ),
            Ok(())
        );
        // Before SupportGenesisHash any hash is refused.
        assert!(
            block_alive(5, "net", &gh, &params(false, false), &txn(1, 9, "net", gh))
                .unwrap_err()
                .ends_with("not allowed")
        );
    }
}
