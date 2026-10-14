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

//! Cross-backend bit-parity beyond the fixed corpus (DIV-001, issue #1948).
//!
//! `tests/falcon_vectors.rs` pins both backends to a 113-record corpus that
//! go-algorand generated. This file attacks the same property from the
//! other side: it feeds the Rust and the vendored-C backends the *same*
//! inputs — many seeds, odd seed lengths, a large number of mutated and
//! garbage signatures/keys — and requires the **entire observable result**
//! (`Result<bool, FalconError>`, i.e. accept/reject *and* the numeric error
//! code) to be identical. Verification decisions are consensus-critical: a
//! single input on which the two disagreed would be a fork risk.
//!
//! Sizes are kept small enough for a debug-profile CI run. Scale them with
//! environment variables for the heavy runs (nightly, or by hand in
//! `--release`):
//!
//! - `FALCON_PARITY_SEEDS`      keygen/sign seeds        (default 8)
//! - `FALCON_PARITY_MUTATIONS`  verify mutations          (default 4000)
//! - `FALCON_PARITY_RANDOM_SIGS` random-byte CT/salt cases (default 3000)
//!
//! Everything is deterministic (fixed xorshift seeds), so a failure is
//! reproducible from the printed case description.

#![cfg(feature = "c-backend")]

use algo_falcon::{
    falcon_convert_compressed_to_ct_with, falcon_keygen_with, falcon_salt_version_with,
    falcon_sign_with, falcon_verify_with, FalconBackend, FALCON_DET1024_PRIVKEY_SIZE,
    FALCON_DET1024_PUBKEY_SIZE, FALCON_DET1024_SIG_COMPRESSED_MAXSIZE,
};
use sha2::{Digest, Sha256};

const R: FalconBackend = FalconBackend::Rust;
const C: FalconBackend = FalconBackend::C;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

fn seed_for(i: usize) -> Vec<u8> {
    Sha256::digest(format!("algod-rust falcon backend parity seed {i}").as_bytes()).to_vec()
}

const MSG_LENS: [usize; 10] = [0, 1, 31, 32, 33, 135, 136, 137, 1000, 4096];

fn msg_for(len: usize, salt: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31).wrapping_add(salt)) as u8)
        .collect()
}

/// Keys, signatures, CT forms, salt versions and verify results are
/// identical for many seeds and message lengths.
#[test]
fn keygen_sign_ct_salt_verify_identical_for_many_seeds() {
    let n = env_usize("FALCON_PARITY_SEEDS", 8);
    for i in 0..n {
        let seed = seed_for(i);
        let (pk_r, sk_r) = falcon_keygen_with(R, &seed).unwrap();
        let (pk_c, sk_c) = falcon_keygen_with(C, &seed).unwrap();
        assert_eq!(pk_r, pk_c, "seed {i}: public key");
        assert_eq!(sk_r, sk_c, "seed {i}: private key");
        for (j, &len) in MSG_LENS.iter().enumerate() {
            // The heavy runs cover every length for every seed; the default
            // run rotates one length per seed (plus the two extremes).
            if n <= 16 && j != i % MSG_LENS.len() && len != 0 && len != 4096 {
                continue;
            }
            let msg = msg_for(len, i);
            let sig_r = falcon_sign_with(R, &sk_r, &msg).unwrap();
            let sig_c = falcon_sign_with(C, &sk_c, &msg).unwrap();
            assert_eq!(sig_r, sig_c, "seed {i} len {len}: compressed signature");
            assert_eq!(
                falcon_convert_compressed_to_ct_with(R, &sig_r),
                falcon_convert_compressed_to_ct_with(C, &sig_c),
                "seed {i} len {len}: CT form"
            );
            assert_eq!(
                falcon_salt_version_with(R, &sig_r),
                falcon_salt_version_with(C, &sig_c),
                "seed {i} len {len}: salt version"
            );
            for backend in [R, C] {
                assert_eq!(
                    falcon_verify_with(backend, &pk_r, &sig_r, &msg),
                    Ok(true),
                    "seed {i} len {len}: {backend} must verify"
                );
            }
        }
    }
}

/// Seeds of any length derive the same keys on both backends (go-algorand
/// always passes 32 bytes, but the C accepts any length including empty).
#[test]
fn keygen_identical_for_every_seed_length() {
    let mut rng = Rng(0xA11C_E5ED_0000_0001);
    for len in [
        0usize, 1, 2, 16, 31, 32, 33, 47, 48, 49, 64, 135, 136, 137, 200,
    ] {
        let seed = rng.bytes(len);
        assert_eq!(
            falcon_keygen_with(R, &seed),
            falcon_keygen_with(C, &seed),
            "seed length {len}"
        );
    }
}

/// A mutation of a valid (public key, signature, message) triple.
fn mutate(
    rng: &mut Rng,
    base: &[(Vec<u8>, Vec<u8>, Vec<u8>)],
    pool: &[Vec<u8>],
) -> (Vec<u8>, Vec<u8>, Vec<u8>, String) {
    let (pk, sig, msg) = &base[rng.below(base.len())];
    let (mut pk, mut sig, mut msg) = (pk.clone(), sig.clone(), msg.clone());
    let desc;
    match rng.below(18) {
        0 => {
            let i = rng.below(sig.len());
            sig[i] ^= 1 << rng.below(8);
            desc = format!("sig bit flip at {i}");
        }
        1 => {
            let i = rng.below(sig.len());
            sig[i] = rng.byte();
            desc = format!("sig byte set at {i}");
        }
        2 => {
            let n = rng.below(sig.len() + 1);
            sig.truncate(n);
            desc = format!("sig truncated to {n}");
        }
        3 => {
            let extra = 1 + rng.below(40);
            sig.extend(rng.bytes(extra));
            desc = format!("sig extended by {extra}");
        }
        4 => {
            sig[0] = rng.byte();
            desc = format!("sig header {:#x}", sig[0]);
        }
        5 => {
            if sig.len() > 1 {
                sig[1] = rng.byte();
            }
            desc = "sig salt-version byte".to_string();
        }
        6 => {
            // A fully random signature body of a plausible length behind a valid header.
            let n = 2 + rng.below(FALCON_DET1024_SIG_COMPRESSED_MAXSIZE - 1);
            sig = rng.bytes(n);
            sig[0] = 0xBA;
            desc = format!("random body, length {n}");
        }
        7 => {
            // Splice the tail of a different signature onto this one.
            let other = &base[rng.below(base.len())].1;
            let cut = rng.below(sig.len().min(other.len()));
            sig.truncate(cut);
            sig.extend_from_slice(&other[cut..]);
            desc = format!("spliced at {cut}");
        }
        8 => {
            let i = rng.below(pk.len());
            pk[i] ^= 1 << rng.below(8);
            desc = format!("pk bit flip at {i}");
        }
        9 => {
            pk = pool[rng.below(pool.len())].clone();
            desc = "pk from another key".to_string();
        }
        10 => {
            let n = FALCON_DET1024_PUBKEY_SIZE;
            pk = rng.bytes(n);
            pk[0] = if rng.below(2) == 0 { 0x0A } else { rng.byte() };
            desc = "random pk".to_string();
        }
        11 => {
            // Public key coefficient pushed to the invalid range [12289, 16383].
            let i = 1 + rng.below(pk.len() - 1);
            pk[i] = 0xFF;
            desc = format!("pk byte {i} = 0xff");
        }
        12 => {
            if !msg.is_empty() {
                let i = rng.below(msg.len());
                msg[i] ^= 1 << rng.below(8);
            } else {
                msg.push(rng.byte());
            }
            desc = "message changed".to_string();
        }
        14 => {
            // Size-validation edge: signature shorter than header + salt version.
            sig.truncate(rng.below(2));
            desc = format!("sig truncated to {}", sig.len());
        }
        15 => {
            // Size-validation edge: signature longer than the 1423-byte maximum.
            let target = FALCON_DET1024_SIG_COMPRESSED_MAXSIZE + 1 + rng.below(64);
            while sig.len() < target {
                sig.push(rng.byte());
            }
            desc = format!("sig extended to {target}");
        }
        16 => {
            // Public key off by a few bytes.
            if rng.below(2) == 0 {
                pk.truncate(pk.len() - 1 - rng.below(4));
            } else {
                pk.push(rng.byte());
            }
            desc = format!("pk resized to {}", pk.len());
        }
        _ => {
            // Multiple independent byte changes in the signature body.
            for _ in 0..1 + rng.below(6) {
                let i = rng.below(sig.len());
                sig[i] = rng.byte();
            }
            desc = "several sig bytes".to_string();
        }
    }
    (pk, sig, msg, desc)
}

/// The verification decision — accept, reject, or the exact error — is the
/// same on both backends for a large number of mutated inputs.
#[test]
fn verify_results_identical_under_mutation() {
    let mutations = env_usize("FALCON_PARITY_MUTATIONS", 4000);
    let mut rng = Rng(0xFA11_0000_0000_0007);
    let mut base = Vec::new();
    let mut pool = Vec::new();
    for i in 0..4 {
        let (pk, sk) = falcon_keygen_with(C, &seed_for(100 + i)).unwrap();
        for len in [0usize, 32, 300] {
            let msg = msg_for(len, i);
            let sig = falcon_sign_with(C, &sk, &msg).unwrap();
            base.push((pk.clone(), sig, msg));
        }
        pool.push(pk);
    }
    // Outcome histogram: proves the mutations reach the accept path, the
    // plain "bad signature" path and the size-validation errors, so equality
    // is not vacuous.
    let mut outcomes: std::collections::BTreeMap<&'static str, usize> = Default::default();
    for case in 0..mutations {
        let (pk, sig, msg, desc) = mutate(&mut rng, &base, &pool);
        let r = falcon_verify_with(R, &pk, &sig, &msg);
        let c = falcon_verify_with(C, &pk, &sig, &msg);
        assert_eq!(
            r,
            c,
            "case {case}: {desc} (sig {} bytes, pk {} bytes)",
            sig.len(),
            pk.len()
        );
        let kind = match &r {
            Ok(true) => "accept",
            Ok(false) => "reject (bad signature)",
            Err(algo_falcon::FalconError::InvalidSignatureSize(_)) => "error: signature size",
            Err(algo_falcon::FalconError::InvalidPubkeySize(_)) => "error: pubkey size",
            Err(_) => "error: other",
        };
        *outcomes.entry(kind).or_default() += 1;
    }
    eprintln!("verify mutation outcomes over {mutations} cases (identical on both backends): {outcomes:?}");
    if mutations >= 2000 {
        assert!(
            outcomes.get("accept").copied().unwrap_or(0) > 0,
            "no mutation was accepted: {outcomes:?}"
        );
        assert!(
            outcomes.get("reject (bad signature)").copied().unwrap_or(0) > mutations / 10,
            "too few ordinary rejections: {outcomes:?}"
        );
        assert!(
            outcomes.get("error: signature size").copied().unwrap_or(0) > 0,
            "signature size errors never exercised: {outcomes:?}"
        );
        assert!(
            outcomes.get("error: pubkey size").copied().unwrap_or(0) > 0,
            "pubkey size errors never exercised: {outcomes:?}"
        );
    }
}

/// Random byte strings through the CT-conversion and salt-version paths
/// agree, including every error code.
#[test]
fn convert_and_salt_identical_on_random_bytes() {
    let cases = env_usize("FALCON_PARITY_RANDOM_SIGS", 3000);
    let mut rng = Rng(0xC0DE_0000_0000_0009);
    // Valid signatures give the converter real compressed bodies to chew on.
    let (_, sk) = falcon_keygen_with(C, &seed_for(200)).unwrap();
    let valid: Vec<Vec<u8>> = (0..6)
        .map(|i| falcon_sign_with(C, &sk, &msg_for(i * 20, i)).unwrap())
        .collect();
    for case in 0..cases {
        let sig = match rng.below(4) {
            0 => {
                let n = 2 + rng.below(FALCON_DET1024_SIG_COMPRESSED_MAXSIZE - 1);
                let mut s = rng.bytes(n);
                s[0] = 0xBA;
                s
            }
            1 => {
                let mut s = valid[rng.below(valid.len())].clone();
                for _ in 0..1 + rng.below(4) {
                    let i = rng.below(s.len());
                    s[i] = rng.byte();
                }
                s
            }
            2 => {
                let mut s = valid[rng.below(valid.len())].clone();
                let n = 2 + rng.below(s.len() - 1);
                s.truncate(n);
                s
            }
            _ => {
                let n = rng.below(FALCON_DET1024_SIG_COMPRESSED_MAXSIZE + 5);
                rng.bytes(n)
            }
        };
        assert_eq!(
            falcon_convert_compressed_to_ct_with(R, &sig),
            falcon_convert_compressed_to_ct_with(C, &sig),
            "case {case}: CT conversion of {} bytes",
            sig.len()
        );
        assert_eq!(
            falcon_salt_version_with(R, &sig),
            falcon_salt_version_with(C, &sig),
            "case {case}: salt version of {} bytes",
            sig.len()
        );
    }
}

/// Signing with a malformed private key fails identically (same error code)
/// on both backends, for the header/format failures an attacker-supplied
/// key file can trigger.
#[test]
fn sign_with_malformed_private_keys_fails_identically() {
    let mut rng = Rng(0x5167_0000_0000_000B);
    let (_, good) = falcon_keygen_with(C, &seed_for(300)).unwrap();
    for case in 0..60 {
        let mut sk = match case % 4 {
            0 => rng.bytes(FALCON_DET1024_PRIVKEY_SIZE),
            1 => {
                let mut k = good.clone();
                let i = rng.below(k.len());
                k[i] = rng.byte();
                k
            }
            2 => {
                let mut k = good.clone();
                k[0] = rng.byte();
                k
            }
            _ => {
                let mut k = rng.bytes(FALCON_DET1024_PRIVKEY_SIZE);
                k[0] = 0x5A;
                k
            }
        };
        // Guard: a key that still decodes to something *valid* would make
        // signing run (correctly, and identically) — keep the test bounded by
        // only comparing the cases the C itself rejects up front.
        let rc = falcon_sign_with(C, &sk, b"msg");
        if rc.is_ok() {
            sk[0] = 0x5A;
            assert_eq!(
                falcon_sign_with(R, &sk, b"msg"),
                falcon_sign_with(C, &sk, b"msg"),
                "case {case}"
            );
            continue;
        }
        assert_eq!(falcon_sign_with(R, &sk, b"msg"), rc, "case {case}");
    }
}
