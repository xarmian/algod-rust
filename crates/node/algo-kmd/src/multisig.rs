//! Multisig address operations — `import_multisig`, `lookup_multisig`,
//! `list_multisig`, `delete_multisig`.
//!
//! Ported from `daemon/kmd/wallet/driver/sqlite.go` (v4.6.0-stable):
//! `ImportMultisigAddr` (sqlite.go:1002), `LookupMultisigPreimage`
//! (sqlite.go:1026), `ListMultisigAddrs` (sqlite.go:1088), and
//! `DeleteMultisigAddr` (sqlite.go:1066). Address derivation reuses
//! [`algo_consensus_crypto::multisig_addr_gen`] so this layer doesn't
//! re-implement the SHA-512/256 hash.

use crate::error::{Error, Result};
use crate::keys::ADDRESS_LEN;
use crate::sqlite::WalletDb;
use crate::wallet::Wallet;

/// Encode a vector of 32-byte public keys as canonical msgpack — an
/// array of `N` `bin` entries, each 32 bytes. Mirrors `msgpackEncode(pks)`
/// at sqlite.go:1016 where `pks` is `[]crypto.PublicKey` and
/// `crypto.PublicKey = [32]byte`. go-codec writes a `[N]byte` array as
/// msgpack bin; we use `rmp::encode::write_bin` for the same on-wire
/// bytes. A fixture test in `tests/multisig_test.rs` asserts a
/// Go-produced blob decodes through this routine and re-encodes byte-
/// identically, so any divergence trips before any wallet op runs.
pub(crate) fn encode_pks(pks: &[[u8; ADDRESS_LEN]]) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(2 + pks.len() * (ADDRESS_LEN + 3));
    rmp::encode::write_array_len(&mut buf, pks.len() as u32).map_err(|_| Error::Crypto)?;
    for pk in pks {
        rmp::encode::write_bin(&mut buf, pk).map_err(|_| Error::Crypto)?;
    }
    Ok(buf)
}

pub(crate) fn decode_pks(bytes: &[u8]) -> Result<Vec<[u8; ADDRESS_LEN]>> {
    let mut cursor = bytes;
    let len = rmp::decode::read_array_len(&mut cursor).map_err(|_| Error::Crypto)? as usize;
    let mut out = Vec::with_capacity(len);
    use std::io::Read;
    for _ in 0..len {
        let bin_len = rmp::decode::read_bin_len(&mut cursor).map_err(|_| Error::Crypto)?;
        if bin_len as usize != ADDRESS_LEN {
            return Err(Error::Crypto);
        }
        let mut pk = [0u8; ADDRESS_LEN];
        cursor.read_exact(&mut pk).map_err(|_| Error::Crypto)?;
        out.push(pk);
    }
    Ok(out)
}

/// Recovered multisig preimage. Mirrors the `(version, threshold, pks)`
/// triple that `LookupMultisigPreimage` returns in Go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigPreimage {
    pub version: u8,
    pub threshold: u8,
    pub pks: Vec<[u8; ADDRESS_LEN]>,
}

impl Wallet {
    /// Compute the multisig address for `(version, threshold, pks)` and
    /// store the preimage in `msig_addrs`. Mirrors
    /// `ImportMultisigAddr` (sqlite.go:1002).
    pub fn import_multisig(
        &self,
        version: u8,
        threshold: u8,
        pks: &[[u8; ADDRESS_LEN]],
    ) -> Result<[u8; ADDRESS_LEN]> {
        let addr = algo_consensus_crypto::multisig_addr_gen(version, threshold, pks)
            .map_err(|_| Error::MultisigInvalid)?;

        let pks_blob = encode_pks(pks)?;
        let db = WalletDb::open(self.db_path())?;
        db.insert_multisig(&addr.0, version, threshold, &pks_blob)?;
        Ok(addr.0)
    }

    /// Recover the `(version, threshold, pks)` preimage for `addr`
    /// and verify it re-derives the same address (tamper check).
    /// Mirrors `LookupMultisigPreimage` (sqlite.go:1026).
    pub fn lookup_multisig(&self, addr: &[u8; ADDRESS_LEN]) -> Result<MultisigPreimage> {
        let db = WalletDb::open(self.db_path())?;
        let (version, threshold, pks_blob) = db.read_multisig_row(addr)?;
        let pks = decode_pks(&pks_blob)?;

        // Tamper guard — Go does the same at sqlite.go:1053–1057.
        let recomputed = algo_consensus_crypto::multisig_addr_gen(version, threshold, &pks)
            .map_err(|_| Error::Tampering)?;
        if &recomputed.0 != addr {
            return Err(Error::Tampering);
        }

        Ok(MultisigPreimage {
            version,
            threshold,
            pks,
        })
    }

    /// List all stored multisig addresses. Mirrors `ListMultisigAddrs`
    /// (sqlite.go:1088). Order is SQLite's natural read order — same
    /// as Go (no `ORDER BY`).
    pub fn list_multisig(&self) -> Result<Vec<[u8; ADDRESS_LEN]>> {
        let db = WalletDb::open(self.db_path())?;
        let raw = db.list_multisig_addresses()?;
        let mut out = Vec::with_capacity(raw.len());
        for bytes in raw {
            if bytes.len() != ADDRESS_LEN {
                return Err(Error::Tampering);
            }
            let mut a = [0u8; ADDRESS_LEN];
            a.copy_from_slice(&bytes);
            out.push(a);
        }
        Ok(out)
    }

    /// Delete a multisig address. Mirrors `DeleteMultisigAddr`
    /// (sqlite.go:1066): password check, then silent `DELETE`.
    pub fn delete_multisig(&self, addr: &[u8; ADDRESS_LEN], password: &[u8]) -> Result<()> {
        self.check_password(password)?;
        let db = WalletDb::open(self.db_path())?;
        db.delete_multisig(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pks_blob_round_trips() {
        let pks: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut pk = [0u8; 32];
                for (j, b) in pk.iter_mut().enumerate() {
                    *b = (i * 32 + j) as u8;
                }
                pk
            })
            .collect();
        let encoded = encode_pks(&pks).unwrap();
        let decoded = decode_pks(&encoded).unwrap();
        assert_eq!(decoded, pks);
    }

    #[test]
    fn decode_rejects_wrong_pk_length() {
        // An array of one 31-byte bin entry — invalid.
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, 1).unwrap();
        rmp::encode::write_bin(&mut buf, &[0u8; 31]).unwrap();
        assert!(matches!(decode_pks(&buf), Err(Error::Crypto)));
    }
}
