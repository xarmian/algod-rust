//! Native post-quantum (Falcon-1024) account authorization wire types and
//! address derivation.
//!
//! Mirrors go-algorand v5.0.0-stable:
//! - `data/transactions/pqsig.go` (`PQSig`)
//! - `data/basics/pq_address.go` (`PQAddressSalt`, `pqAddressPreimage`, `PQAddress`, `CanonicalPQAddressSalt`)
//! - `data/transactions/logic/program.go` (`PQDelegatedProgram`, added by commit `ef838f4e9`)
//! - `protocol/hash.go` (`PostQuantumAddress = "PQA"`, `PostQuantumDelegatedProgram = "PQProgram"`)
//!
//! Scheme-specific signature verification (Falcon-1024) is NOT implemented
//! here — this module only carries the wire types and the deterministic
//! address-derivation hash. Verification wiring (group well-formedness,
//! pre-activation rejection, fee surcharge, in-place PQ/PQ-delegated-lsig
//! verification) lives in `algo-validate`.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest as Sha2Digest, Sha512_256};

use crate::Address;

/// Domain separation prefix for post-quantum address derivation
/// (`protocol.PostQuantumAddress = "PQA"`).
const PQA_HASH_PREFIX: &[u8] = b"PQA";

/// Domain separation prefix for post-quantum delegated LogicSig program
/// hashing (`protocol.PostQuantumDelegatedProgram = "PQProgram"`).
const PQ_DELEGATED_PROGRAM_HASH_PREFIX: &[u8] = b"PQProgram";

/// A 2-byte ASCII identifier of a post-quantum account authorization scheme
/// (Go: `protocol.PQScheme = [2]byte`). Only Falcon-1024 (`"f1"`) is
/// currently supported/enabled; the reserved-but-unwired Falcon-512
/// (`"f2"`) tag is a known scheme constant upstream but has no registered
/// verifier and is never enabled.
pub const PQ_SCHEME_FALCON1024: [u8; 2] = *b"f1";

/// A 1-byte salt that selects an address for a post-quantum public key when
/// deriving a 32-byte address; it is public and included in the address
/// derivation. Mirrors go's `basics.PQAddressSalt uint8`
/// (`data/basics/pq_address.go`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PQAddressSalt(pub u8);

impl Serialize for PQAddressSalt {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.0)
    }
}

impl<'de> Deserialize<'de> for PQAddressSalt {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(PQAddressSalt(u8::deserialize(deserializer)?))
    }
}

/// A post-quantum transaction authorization proof (Go: `transactions.PQSig`,
/// `data/transactions/pqsig.go`). Carried as the `pqsig` field on both
/// `SignedTransaction` and `LogicSig` (`Option<PQSig>`, matching this repo's
/// convention for optional nested-struct wire fields — `None` corresponds to
/// Go's `PQSig.Blank()`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PQSig {
    /// The PQ scheme tag (Go: `protocol.PQScheme`, `codec:"sch"`).
    #[serde(rename = "sch", default, skip_serializing_if = "is_zero_scheme")]
    pub scheme: [u8; 2],

    /// The salt used in PQ address derivation (`codec:"slt"`).
    #[serde(rename = "slt", default, skip_serializing_if = "is_zero_salt")]
    pub salt: PQAddressSalt,

    /// The PQ public key (`codec:"pk"`).
    #[serde(rename = "pk", default, skip_serializing_if = "bytebuf_is_empty")]
    pub public_key: ByteBuf,

    /// The PQ signature (`codec:"sig"`).
    #[serde(rename = "sig", default, skip_serializing_if = "bytebuf_is_empty")]
    pub signature: ByteBuf,
}

fn is_zero_scheme(s: &[u8; 2]) -> bool {
    *s == [0u8; 2]
}

fn is_zero_salt(s: &PQAddressSalt) -> bool {
    s.0 == 0
}

fn bytebuf_is_empty(b: &ByteBuf) -> bool {
    b.as_slice().is_empty()
}

impl PQSig {
    /// Mirrors go's `PQSig.Blank()`: true when every field is at its zero
    /// value (no PQ authorization envelope present at all).
    pub fn blank(&self) -> bool {
        self.scheme == [0u8; 2]
            && self.salt.0 == 0
            && self.public_key.is_empty()
            && self.signature.is_empty()
    }

    /// Mirrors go's `PQSig.Address()`: the authorizer address derived from
    /// this PQSig's scheme, salt, and public key.
    pub fn address(&self) -> Address {
        pq_address(self.scheme, self.salt, &self.public_key)
    }
}

/// `PQDelegatedProgram{Addr, Program}` (Go: `data/transactions/logic/program.go`,
/// added by commit `ef838f4e9`) is what a PQ-delegated LogicSig signs: the
/// hash preimage `Addr || Program` under the `"PQProgram"` domain tag.
#[derive(Debug, Clone, PartialEq)]
pub struct PQDelegatedProgram {
    pub addr: Address,
    pub program: Vec<u8>,
}

impl PQDelegatedProgram {
    /// The raw bytes a PQ-delegated LogicSig's Falcon signature is computed
    /// over: `"PQProgram" || Addr || Program` (Go's `HashRep`, which prepends
    /// the `protocol.HashID` domain tag but does NOT hash — Falcon signs the
    /// tagged bytes directly; see `crypto.HashRep`/`FalconSigner.Sign`).
    pub fn to_be_signed(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(PQ_DELEGATED_PROGRAM_HASH_PREFIX.len() + 32 + self.program.len());
        out.extend_from_slice(PQ_DELEGATED_PROGRAM_HASH_PREFIX);
        out.extend_from_slice(&self.addr.0);
        out.extend_from_slice(&self.program);
        out
    }
}

/// Returns the address derived from a PQ signature scheme, an explicit salt,
/// and a scheme-canonical public key: `SHA512/256("PQA" || scheme || salt ||
/// pk)`. Mirrors go's `basics.PQAddress(scheme, salt, pk)`
/// (`data/basics/pq_address.go`).
pub fn pq_address(scheme: [u8; 2], salt: PQAddressSalt, pk: &[u8]) -> Address {
    let mut payload = Vec::with_capacity(2 + 1 + pk.len());
    payload.extend_from_slice(&scheme);
    payload.push(salt.0);
    payload.extend_from_slice(pk);

    let mut hasher = Sha512_256::new();
    hasher.update(PQA_HASH_PREFIX);
    hasher.update(&payload);
    let hash: [u8; 32] = hasher.finalize().into();
    Address(hash)
}

/// Returns the lowest salt (ascending `0..=255` scan) whose derived address
/// for a `scheme`/`publicKey` pair is `IsPQCompliant()` (not a valid
/// ed25519 curve point), and that address. Mirrors go's
/// `basics.CanonicalPQAddressSalt(scheme, publicKey)`
/// (`data/basics/pq_address.go`). Returns `None` in the (probability
/// ~2^-256) event that no compliant salt exists in range, matching
/// upstream's `errNoCanonicalPQAddressSalt`.
pub fn canonical_pq_address_salt(
    scheme: [u8; 2],
    public_key: &[u8],
) -> Option<(PQAddressSalt, Address)> {
    for salt in 0..=u8::MAX {
        let addr = pq_address(scheme, PQAddressSalt(salt), public_key);
        if addr.is_pq_compliant() {
            return Some((PQAddressSalt(salt), addr));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pqsig_blank_matches_default() {
        assert!(PQSig::default().blank());
    }

    #[test]
    fn pqsig_nonblank_when_any_field_set() {
        let sig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            ..Default::default()
        };
        assert!(!sig.blank());
    }

    #[test]
    fn canonical_pq_address_salt_is_deterministic_and_pq_compliant() {
        let pk = vec![0x42u8; 1793];
        let (salt, addr) = canonical_pq_address_salt(PQ_SCHEME_FALCON1024, &pk)
            .expect("a compliant salt must exist within 0..=255 with overwhelming probability");
        assert!(addr.is_pq_compliant());
        // Re-deriving with the same salt must reproduce the same address.
        assert_eq!(pq_address(PQ_SCHEME_FALCON1024, salt, &pk), addr);
    }

    #[test]
    fn canonical_pq_address_salt_scans_ascending_from_zero() {
        // The first salt (0..=255, ascending) whose derived address is
        // PQ-compliant must be returned — verify by checking every salt
        // strictly below the returned one was NOT compliant.
        let pk = vec![0x7fu8; 64];
        let (salt, _) = canonical_pq_address_salt(PQ_SCHEME_FALCON1024, &pk).unwrap();
        for s in 0..salt.0 {
            let addr = pq_address(PQ_SCHEME_FALCON1024, PQAddressSalt(s), &pk);
            assert!(
                !addr.is_pq_compliant(),
                "salt {s} was PQ-compliant but a smaller salt than the returned {} was found",
                salt.0
            );
        }
    }

    #[test]
    fn pq_address_changes_with_scheme_salt_or_pk() {
        let pk = vec![1u8; 8];
        let base = pq_address(PQ_SCHEME_FALCON1024, PQAddressSalt(0), &pk);
        assert_ne!(
            base,
            pq_address(PQ_SCHEME_FALCON1024, PQAddressSalt(1), &pk)
        );
        assert_ne!(base, pq_address(*b"f2", PQAddressSalt(0), &pk));
        assert_ne!(
            base,
            pq_address(PQ_SCHEME_FALCON1024, PQAddressSalt(0), &[2u8; 8])
        );
    }

    #[test]
    fn pq_delegated_program_to_be_signed_uses_pqprogram_domain_tag() {
        let dp = PQDelegatedProgram {
            addr: Address([9u8; 32]),
            program: vec![1, 2, 3],
        };
        let bytes = dp.to_be_signed();
        assert!(bytes.starts_with(b"PQProgram"));
        assert_eq!(
            &bytes[b"PQProgram".len()..b"PQProgram".len() + 32],
            &[9u8; 32]
        );
        assert_eq!(&bytes[b"PQProgram".len() + 32..], &[1, 2, 3]);
    }
}
