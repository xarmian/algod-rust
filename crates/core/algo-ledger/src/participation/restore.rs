//! Partkey-DB reader — Rust equivalent of go-algorand's
//! `account.RestoreParticipation`.
//!
//! Reads the algokey-flavor partkey sqlite schema (one
//! `ParticipationAccount` row + an optional `StateProofKeys` table)
//! and assembles a [`crate::participation::Participation`].
//!
//! Reference:
//! - `../go-algorand/data/account/account.go:157` — SELECT query
//! - `../go-algorand/data/account/participation.go::RestoreParticipation`
//! - `../go-algorand/data/account/persistentMerkleSignatureScheme.go:143`
//!   — StateProofKeys query
//!
//! ## Schema
//!
//! Produced by `algokey part generate` (Go v4.5.1-stable):
//!
//! ```sql
//! CREATE TABLE ParticipationAccount (
//!     parent BLOB,
//!     vrf BLOB,         -- msgpack {PK: [32]byte, SK: [64]byte}
//!     voting BLOB,      -- msgpack OneTimeSignatureSecrets
//!     firstValid INTEGER,
//!     lastValid INTEGER,
//!     keyDilution INTEGER NOT NULL DEFAULT 0,
//!     stateProof BLOB  -- msgpack merklesignature.Secrets (sans ephemeral keys)
//! );
//! CREATE TABLE StateProofKeys (
//!     id    INTEGER PRIMARY KEY,
//!     round INTEGER,    -- committed round for this key
//!     key   BLOB        -- msgpack FalconSigner
//! );
//! ```
//!
//! The `stateProof` column holds the `merklesignature.Secrets`
//! metadata (commitment, first_valid, key_lifetime). Individual
//! ephemeral keys live in `StateProofKeys`, one row per round.

use algo_consensus_crypto::merklesig::{self, FalconSigner};
use algo_consensus_crypto::{OneTimeSignatureSecrets, VrfKeypair, VrfPrivkey, VrfPubkey};
use algo_types::{Address, Round};
use rusqlite::OptionalExtension;
use thiserror::Error;

use crate::erasable_db::ErasableDb;
use crate::participation::Participation;

/// Errors from [`restore_participation`].
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying sqlite read failure.
    #[error("sqlite read: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// `ParticipationAccount` table missing or empty.
    #[error("partkey DB has no ParticipationAccount row")]
    Empty,
    /// One of the BLOB columns failed msgpack decoding. The `field`
    /// name names which column.
    #[error("decode `{field}`: {reason}")]
    Decode { field: &'static str, reason: String },
    /// Parent address column was the wrong length (not 32 bytes).
    #[error("parent address must be 32 bytes, got {0}")]
    BadParentLength(usize),
}

/// Read a Go-produced partkey DB into a typed [`Participation`].
///
/// Mirrors `RestoreParticipation` at
/// `../go-algorand/data/account/participation.go`. Closes the
/// implicit read transaction before returning (matches Go's
/// `defer partdb.Close()` pattern at `algokey/keyreg.go:194`).
/// Raw `ParticipationAccount` row, pulled in a single sqlite call so the
/// read-side transaction can close before we start msgpack-decoding.
struct PartkeyRow {
    parent: Vec<u8>,
    vrf: Vec<u8>,
    voting: Vec<u8>,
    first_valid: i64,
    last_valid: i64,
    key_dilution: i64,
    state_proof: Option<Vec<u8>>,
}

pub fn restore_participation(db: &ErasableDb) -> Result<Participation, Error> {
    let conn = db.conn();

    // We unconditionally SELECT `stateProof`. Go's `RestoreParticipation`
    // first runs `Migrate` to add this column to pre-v3 partkey DBs
    // (schema v2, predating state proofs). algod-rust intentionally
    // does NOT preserve back-compat with non-existent deployments
    // (CONVE-197): no v2 partkey DB was ever in production with this
    // tool, so handling that legacy shape would be a deferred-cleanup
    // anti-pattern. Any Go-produced partkey DB from v4.5.1-stable has
    // the stateProof column.
    let row: Option<PartkeyRow> = conn
        .query_row(
            "SELECT parent, vrf, voting, firstValid, lastValid, keyDilution, stateProof \
             FROM ParticipationAccount",
            [],
            |row| {
                Ok(PartkeyRow {
                    parent: row.get(0)?,
                    vrf: row.get(1)?,
                    voting: row.get(2)?,
                    first_valid: row.get(3)?,
                    last_valid: row.get(4)?,
                    key_dilution: row.get(5)?,
                    state_proof: row.get(6)?,
                })
            },
        )
        .optional()?;

    let Some(PartkeyRow {
        parent: parent_bytes,
        vrf: vrf_blob,
        voting: voting_blob,
        first_valid,
        last_valid,
        key_dilution,
        state_proof: sp_blob,
    }) = row
    else {
        return Err(Error::Empty);
    };

    // Parent: raw 32-byte pubkey.
    if parent_bytes.len() != 32 {
        return Err(Error::BadParentLength(parent_bytes.len()));
    }
    let mut parent_arr = [0u8; 32];
    parent_arr.copy_from_slice(&parent_bytes);
    let parent = Address(parent_arr);

    // VRF: msgpack {PK: [32]byte, SK: [64]byte} → VrfKeypair.
    let vrf = decode_vrf_blob(&vrf_blob)?;

    // Voting: msgpack OneTimeSignatureSecrets.
    let voting =
        OneTimeSignatureSecrets::from_msgpack(&voting_blob).map_err(|e| Error::Decode {
            field: "voting",
            reason: e,
        })?;

    // StateProof (optional): msgpack merklesignature.Secrets.
    // Go writes this as an empty blob (or NULL) when the partkey was
    // generated without state-proof support; check both cases.
    let state_proof_secrets = match sp_blob {
        None => None,
        Some(b) if b.is_empty() => None,
        Some(b) => {
            let (secrets, _) = merklesig::Secrets::from_msgpack(&b).map_err(|e| Error::Decode {
                field: "stateProof",
                reason: e,
            })?;
            Some(secrets)
        }
    };

    // StateProofKeys: load every (round, key) row.
    let ephemeral_keys = load_state_proof_keys(conn)?;

    // Attach the ephemeral keys to the secrets metadata, if any.
    let state_proof_secrets = attach_ephemeral_keys(state_proof_secrets, ephemeral_keys);

    Ok(Participation {
        parent,
        vrf,
        voting,
        first_valid: Round(first_valid as u64),
        last_valid: Round(last_valid as u64),
        key_dilution: key_dilution as u64,
        state_proof_secrets,
    })
}

/// Decode Go's `crypto.VRFSecrets` msgpack blob `{PK: [32]byte, SK: [64]byte}`
/// into a [`VrfKeypair`].
///
/// libsodium's `crypto_vrf_keypair_from_seed` lays the 64-byte SK out as
/// `[seed (32) || derived_pk (32)]`. We extract the first 32 bytes as
/// the seed, construct `VrfPrivkey::from_seed`, and verify the embedded
/// PK matches what the keypair derives. A mismatch indicates a corrupt
/// or non-libsodium-compatible partkey DB.
fn decode_vrf_blob(blob: &[u8]) -> Result<VrfKeypair, Error> {
    let (pk_bytes, sk_bytes) = parse_vrf_msgpack(blob).map_err(|e| Error::Decode {
        field: "vrf",
        reason: e,
    })?;
    if pk_bytes.len() != 32 {
        return Err(Error::Decode {
            field: "vrf.PK",
            reason: format!("expected 32 bytes, got {}", pk_bytes.len()),
        });
    }
    if sk_bytes.len() != 64 {
        return Err(Error::Decode {
            field: "vrf.SK",
            reason: format!("expected 64 bytes, got {}", sk_bytes.len()),
        });
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&sk_bytes[..32]);

    let sk = VrfPrivkey::from_seed(seed);
    let kp = VrfKeypair::from_seed(seed);
    // Sanity check: libsodium-derived PK should match the embedded PK.
    // If this ever diverges, the partkey DB was produced by a
    // non-compatible VRF impl and we shouldn't silently use it.
    if kp.pk.0 != pk_arr {
        return Err(Error::Decode {
            field: "vrf",
            reason: format!(
                "embedded PK {} does not match seed-derived PK {} — DB may be from \
                 a non-libsodium VRF implementation",
                hex::encode(pk_arr),
                hex::encode(kp.pk.0)
            ),
        });
    }
    // Use the embedded PK verbatim to preserve byte-equality with Go.
    let _ = sk; // keep the explicit construction for symmetry / future zeroize.
    Ok(VrfKeypair {
        pk: VrfPubkey(pk_arr),
        sk: VrfPrivkey::from_seed(seed),
    })
}

/// Parse the inline `{PK: bin32, SK: bin64}` map. We avoid taking a
/// dependency on `rmpv` here so the helper stays compact and
/// auditable; the format is tightly fixed and only used for partkey
/// reads. Field-order tolerance matches msgpack maps (entries can
/// appear in any order).
fn parse_vrf_msgpack(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut cur = blob;
    let map_len = match cur.first().copied() {
        Some(b) if (0x80..=0x8f).contains(&b) => {
            let n = (b & 0x0f) as usize;
            cur = &cur[1..];
            n
        }
        Some(b) => return Err(format!("expected fixmap at start, got 0x{b:02x}")),
        None => return Err("empty blob".into()),
    };
    if map_len != 2 {
        return Err(format!("expected 2-entry map, got {map_len}"));
    }

    let mut pk = None;
    let mut sk = None;
    for _ in 0..map_len {
        let (key, rest) = read_fixstr(cur)?;
        cur = rest;
        let (value, rest) = read_bin(cur)?;
        cur = rest;
        match key {
            "PK" => pk = Some(value),
            "SK" => sk = Some(value),
            other => return Err(format!("unexpected vrf field `{other}`")),
        }
    }
    Ok((
        pk.ok_or_else(|| "missing PK field".to_string())?,
        sk.ok_or_else(|| "missing SK field".to_string())?,
    ))
}

fn read_fixstr(buf: &[u8]) -> Result<(&str, &[u8]), String> {
    let &first = buf.first().ok_or("eof reading fixstr")?;
    let len = if (0xa0..=0xbf).contains(&first) {
        (first & 0x1f) as usize
    } else {
        return Err(format!("expected fixstr, got 0x{first:02x}"));
    };
    let bytes = buf
        .get(1..1 + len)
        .ok_or_else(|| format!("fixstr truncated: need {len} bytes"))?;
    let s = std::str::from_utf8(bytes).map_err(|e| format!("fixstr utf8: {e}"))?;
    Ok((s, &buf[1 + len..]))
}

fn read_bin(buf: &[u8]) -> Result<(Vec<u8>, &[u8]), String> {
    let &first = buf.first().ok_or("eof reading bin")?;
    let (len, header_len) = match first {
        0xc4 => {
            let n = *buf.get(1).ok_or("bin8 len truncated")? as usize;
            (n, 2)
        }
        0xc5 => {
            let bytes = buf.get(1..3).ok_or("bin16 len truncated")?;
            let n = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
            (n, 3)
        }
        0xc6 => {
            let bytes = buf.get(1..5).ok_or("bin32 len truncated")?;
            let n = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
            (n, 5)
        }
        _ => return Err(format!("expected bin family, got 0x{first:02x}")),
    };
    let data = buf
        .get(header_len..header_len + len)
        .ok_or_else(|| format!("bin truncated: need {len} bytes"))?;
    Ok((data.to_vec(), &buf[header_len + len..]))
}

/// Read every `StateProofKeys` row, msgpack-decoding each into a
/// `FalconSigner`. Returns rows sorted by ascending round.
fn load_state_proof_keys(conn: &rusqlite::Connection) -> Result<Vec<(u64, FalconSigner)>, Error> {
    // First check the table exists. Go's partkey DBs always have it;
    // older / hand-edited DBs may not. Treat missing as "no keys".
    let table_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='StateProofKeys'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    if table_exists == 0 {
        return Ok(Vec::new());
    }

    let mut stmt = conn.prepare("SELECT round, key FROM StateProofKeys ORDER BY round ASC")?;
    let rows = stmt.query_map([], |row| {
        let round: i64 = row.get(0)?;
        let blob: Vec<u8> = row.get(1)?;
        Ok((round as u64, blob))
    })?;

    let mut out = Vec::new();
    for r in rows {
        let (round, blob) = r?;
        let (signer, _) = FalconSigner::from_msgpack(&blob).map_err(|e| Error::Decode {
            field: "StateProofKeys.key",
            reason: e,
        })?;
        out.push((round, signer));
    }
    Ok(out)
}

/// Attach a vector of `(round, FalconSigner)` rows to a parsed
/// `merklesig::Secrets`. The metadata blob stored in
/// `ParticipationAccount.stateProof` carries the merkle commitment and
/// `key_lifetime` but no signing keys; we add them here so callers can
/// sign without further sqlite round-trips. If the metadata is `None`,
/// returns `None` regardless of how many keys were loaded — matches
/// Go's `partkey.StateProofSecrets != nil` check at
/// `cmd/algokey/part.go:170`.
fn attach_ephemeral_keys(
    secrets: Option<merklesig::Secrets>,
    rows: Vec<(u64, FalconSigner)>,
) -> Option<merklesig::Secrets> {
    let mut secrets = secrets?;
    if rows.is_empty() {
        // No ephemeral keys present (typical for first/last < key_lifetime).
        // Leave the existing ephemeral_keys vector (likely empty) untouched.
        return Some(secrets);
    }
    // Compute first_key_offset relative to the metadata's first_valid:
    // mirrors algo-ledger::participation::store::restore_state_proof_keys
    // (which the writer side will mirror in Phase C).
    let first_valid = secrets.signer_context.first_valid;
    let key_lifetime = secrets.signer_context.key_lifetime;
    let first_round = rows[0].0;
    if key_lifetime > 0 {
        secrets.first_key_offset =
            merklesig::round_to_index(first_valid, first_round, key_lifetime);
    }
    secrets.ephemeral_keys = rows.into_iter().map(|(_, sig)| sig).collect();
    Some(secrets)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inline VRF msgpack decoder: `{PK: [32]byte, SK: [64]byte}` →
    /// `(pk, sk)`. Pinned bytes mirror what `algokey part generate`
    /// emits.
    #[test]
    fn vrf_msgpack_decoder_handles_pk_sk_map() {
        // Hand-built fixmap with PK = [1; 32], SK = [2; 64].
        let mut blob = Vec::new();
        blob.push(0x82); // fixmap of 2
        blob.extend_from_slice(&[0xa2, b'P', b'K']);
        blob.extend_from_slice(&[0xc4, 0x20]); // bin8, len 32
        blob.extend_from_slice(&[1u8; 32]);
        blob.extend_from_slice(&[0xa2, b'S', b'K']);
        blob.extend_from_slice(&[0xc4, 0x40]); // bin8, len 64
        blob.extend_from_slice(&[2u8; 64]);

        let (pk, sk) = parse_vrf_msgpack(&blob).expect("parse");
        assert_eq!(pk, vec![1u8; 32]);
        assert_eq!(sk, vec![2u8; 64]);
    }

    /// Wrong-length map is rejected with a clear error.
    #[test]
    fn vrf_msgpack_rejects_non_two_entry_maps() {
        let blob = [0x83u8, 0xa0, 0xc4, 0x00]; // 3-entry map header
        let err = parse_vrf_msgpack(&blob).unwrap_err();
        assert!(err.contains("2-entry map"), "{err}");
    }
}
