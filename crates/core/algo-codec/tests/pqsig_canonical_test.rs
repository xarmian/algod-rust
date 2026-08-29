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

//! Byte-exact conformance tests for `PQSig`-bearing `SignedTransaction`/
//! `LogicSig` canonical msgpack encoding, against fixtures captured from a
//! **real go-algorand v5.0.0-stable `algokey pq` run** (issue #707).
//!
//! Unlike the hand-computed oracle tests in `canonical.rs`
//! (`canonical_encode_pqsig_matches_expected_bytes`,
//! `canonical_encode_pqsig_omits_zero_fields` — verified against go's
//! *documented* canonical-encoding rules), these fixtures are the literal
//! output bytes of a go-algorand binary: `algokey pq sign` (for
//! `SignedTxn.PQsig`) and `algokey pq sign-program` (for
//! `LogicSig.PQsig`), built from `../go-algorand` pinned to
//! `v5.0.0-stable` with `make libsodium` (see
//! `scripts/capture-pqsig-fixtures.sh` for the exact capture recipe).
//!
//! Both fixtures use the same deterministic Falcon-1024 key, derived via
//! `algokey pq import -m "<mnemonic>"` from the well-known all-zero test
//! mnemonic (`abandon abandon ... invest`) shared with
//! `algo-consensus-crypto`'s passphrase-parity corpus — so the capture is
//! reproducible byte-for-byte from a clean go-algorand checkout.

use std::fs;
use std::path::{Path, PathBuf};

use algo_codec::{canonical_encode_logicsig, canonical_encode_signed_transaction};
use algo_types::{LogicSig, SignedTransaction};

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pqsig")
}

fn load_hex_fixture(name: &str) -> Vec<u8> {
    let path = fixtures_root().join(name);
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    hex::decode(raw.trim()).unwrap_or_else(|e| panic!("invalid hex in {}: {e}", path.display()))
}

/// A real go-algorand-produced `SignedTxn` carrying a top-level
/// `PQsig` (and `AuthAddr`, since the payment's `Sender` differs from the
/// PQ signing address) must decode via `rmp_serde` and re-encode
/// byte-identically through `canonical_encode_signed_transaction`.
#[test]
fn signed_transaction_pqsig_byte_exact_against_go_fixture() {
    let expected = load_hex_fixture("signed_txn_with_pqsig.canonical.hex");

    let decoded: SignedTransaction = rmp_serde::from_slice(&expected)
        .expect("decode go-captured SignedTxn with PQsig via rmp_serde");

    assert!(
        decoded.pqsig.is_some(),
        "fixture must carry a PQsig — capture regressed to an unsigned txn"
    );
    assert!(
        decoded.auth_addr.is_some(),
        "fixture's Sender differs from the PQ signing address, so AuthAddr \
         (sgnr) must be set by `algokey pq sign` — capture regressed"
    );

    let actual = canonical_encode_signed_transaction(&decoded);
    assert_eq!(
        hex::encode(&actual),
        hex::encode(&expected),
        "byte-exact mismatch re-encoding go-captured SignedTxn.PQsig fixture"
    );
}

/// A real go-algorand-produced `LogicSig` carrying a delegated `PQsig`
/// (`algokey pq sign-program`) must decode via `rmp_serde` and re-encode
/// byte-identically through `canonical_encode_logicsig`.
#[test]
fn logicsig_pqsig_byte_exact_against_go_fixture() {
    let expected = load_hex_fixture("logicsig_with_pqsig.canonical.hex");

    let decoded: LogicSig = rmp_serde::from_slice(&expected)
        .expect("decode go-captured LogicSig with PQsig via rmp_serde");

    assert!(
        decoded.pqsig.is_some(),
        "fixture must carry a PQsig — capture regressed to an unsigned LogicSig"
    );
    assert_eq!(&decoded.logic[..], &[0x06, 0x81, 0x01][..]);

    let actual = canonical_encode_logicsig(&decoded);
    assert_eq!(
        hex::encode(&actual),
        hex::encode(&expected),
        "byte-exact mismatch re-encoding go-captured LogicSig.PQsig fixture"
    );
}

/// Sanity check that the fixture files actually exist and are non-trivial,
/// so a future accidental deletion fails loudly here rather than the two
/// tests above silently vanishing along with the file (there is no
/// SKIPPED path for these fixtures — unlike the trackerdb corpus, they
/// are committed in-tree and don't depend on a live localnet capture).
#[test]
fn pqsig_fixture_files_present() {
    for name in [
        "signed_txn_with_pqsig.canonical.hex",
        "logicsig_with_pqsig.canonical.hex",
    ] {
        let path = fixtures_root().join(name);
        assert!(
            Path::new(&path).is_file(),
            "missing fixture {}",
            path.display()
        );
        let bytes = load_hex_fixture(name);
        assert!(bytes.len() > 100, "{name} fixture looks truncated");
    }
}
