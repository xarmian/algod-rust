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

//! go's chain building for a server certificate that is a certificate
//! authority itself (issue #2532).
//!
//! webpki refuses a CA certificate as the end entity
//! (`CaUsedAsEndEntity`); go's `x509.Certificate.Verify` accepts it when it
//! chains to a trusted root. This module is that part of `Verify`
//! (`buildChains`, `CheckSignatureFrom`, `isValid`, `checkChainForKeyUsage`)
//! for the request `goal` makes (`ServerAuth`, the system roots): the leaf
//! itself being a root, or a path through the presented intermediates to a
//! root, every signature checked with the crypto provider's algorithms.
//!
//! It never relaxes a check: a certificate it cannot judge (name
//! constraints, an unknown critical extension, an unsupported signature
//! algorithm, a malformed field) is refused, with go's text where it has
//! one and the unknown-authority error otherwise.

use crate::x509_leaf::{parse_time, tlv, validity_error};
use rustls::pki_types::SignatureVerificationAlgorithm;

/// What `Verify` reads of one certificate.
#[derive(Debug)]
struct Cert<'a> {
    der: &'a [u8],
    /// The `tbsCertificate` element, header included (the signed bytes).
    tbs: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    /// The `AlgorithmIdentifier` of the public key, header included.
    spki_alg: &'a [u8],
    /// The public key bits.
    public_key: &'a [u8],
    /// The `AlgorithmIdentifier` of the signature, header included.
    sig_alg: &'a [u8],
    signature: &'a [u8],
    not_before: i64,
    not_after: i64,
    version3: bool,
    /// `basicConstraints`: whether present, `cA`, and `pathLenConstraint`.
    bc_valid: bool,
    is_ca: bool,
    max_path_len: Option<u64>,
    /// `keyUsage` bits (first byte), 0 when absent.
    key_usage: u8,
    /// `extKeyUsage` OIDs, `None` when absent.
    eku: Option<Vec<&'a [u8]>>,
    has_name_constraints: bool,
    unhandled_critical: bool,
}

const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25];
const OID_NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
/// Extensions go handles or ignores when critical: subject key id, subject
/// alternative name, authority key id, CRL distribution points, certificate
/// policies, authority information access.
const HANDLED: &[&[u8]] = &[
    &[0x55, 0x1d, 0x0e],
    &[0x55, 0x1d, 0x11],
    &[0x55, 0x1d, 0x23],
    &[0x55, 0x1d, 0x1f],
    &[0x55, 0x1d, 0x20],
    &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01],
];
const EKU_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
const KEY_CERT_SIGN: u8 = 0x04;

/// The element `b` starts with, header included, and what follows it.
fn whole(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let (_, _, rest) = tlv(b)?;
    Some((&b[..b.len() - rest.len()], rest))
}

fn parse(der: &[u8]) -> Option<Cert<'_>> {
    let (_, cert, _) = tlv(der)?;
    let (tbs_tlv, after_tbs) = whole(cert)?;
    let (_, tbs, _) = tlv(tbs_tlv)?;
    let (sig_alg, rest) = whole(after_tbs)?;
    let (tag, bits, _) = tlv(rest)?;
    if tag != 0x03 || *bits.first()? != 0 {
        return None;
    }
    let signature = &bits[1..];

    let mut rest = tbs;
    let mut version3 = false;
    let (tag, v, after) = tlv(rest)?;
    if tag == 0xa0 {
        let (_, n, _) = tlv(v)?;
        version3 = n == [2];
        rest = after;
    }
    // serial, signature
    for _ in 0..2 {
        rest = tlv(rest)?.2;
    }
    let (issuer, rest) = whole(rest)?;
    let (_, validity, rest) = tlv(rest)?;
    let (t1, nb, v) = tlv(validity)?;
    let (t2, na, _) = tlv(v)?;
    let (subject, rest) = whole(rest)?;
    let (_, spki, rest) = tlv(rest)?;
    let (spki_alg, after_alg) = whole(spki)?;
    let (tag, key_bits, _) = tlv(after_alg)?;
    if tag != 0x03 || *key_bits.first()? != 0 {
        return None;
    }
    let mut c = Cert {
        der,
        tbs: tbs_tlv,
        issuer,
        subject,
        spki_alg,
        public_key: &key_bits[1..],
        sig_alg,
        signature,
        not_before: parse_time(t1, nb)?,
        not_after: parse_time(t2, na)?,
        version3,
        bc_valid: false,
        is_ca: false,
        max_path_len: None,
        key_usage: 0,
        eku: None,
        has_name_constraints: false,
        unhandled_critical: false,
    };
    let mut rest = rest;
    while !rest.is_empty() {
        let (tag, body, after) = tlv(rest)?;
        rest = after;
        if tag != 0xa3 {
            continue;
        }
        let (_, mut exts, _) = tlv(body)?;
        while !exts.is_empty() {
            let (_, ext, after) = tlv(exts)?;
            exts = after;
            let (_, oid, e) = tlv(ext)?;
            let (mut t, mut value, mut rest_e) = tlv(e)?;
            let mut critical = false;
            if t == 0x01 {
                critical = value == [0xff];
                (t, value, rest_e) = tlv(rest_e)?;
            }
            let _ = rest_e;
            if t != 0x04 {
                return None;
            }
            match oid {
                OID_BASIC_CONSTRAINTS => {
                    c.bc_valid = true;
                    let (_, mut seq, _) = tlv(value)?;
                    if let Some((0x01, b, after)) = tlv(seq) {
                        c.is_ca = b == [0xff];
                        seq = after;
                    }
                    if let Some((0x02, n, _)) = tlv(seq) {
                        if n.len() > 4 || n.first().is_some_and(|b| b & 0x80 != 0) {
                            return None;
                        }
                        c.max_path_len = Some(n.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b)));
                    }
                }
                OID_KEY_USAGE => {
                    let (tag, bits, _) = tlv(value)?;
                    if tag != 0x03 {
                        return None;
                    }
                    c.key_usage = bits.get(1).copied().unwrap_or(0);
                }
                OID_EKU => {
                    let (_, mut oids, _) = tlv(value)?;
                    let mut list = Vec::new();
                    while !oids.is_empty() {
                        let (tag, o, after) = tlv(oids)?;
                        if tag != 0x06 {
                            return None;
                        }
                        list.push(o);
                        oids = after;
                    }
                    c.eku = Some(list);
                }
                OID_NAME_CONSTRAINTS => c.has_name_constraints = true,
                other if critical && !HANDLED.contains(&other) => c.unhandled_critical = true,
                _ => {}
            }
        }
    }
    Some(c)
}

/// The kind of failure, for the error text.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    /// `x509: certificate signed by unknown authority`, with go's hint: the
    /// first candidate authority that failed and why.
    Unknown(Option<(String, String)>),
    /// `x509: certificate specifies an incompatible key usage`.
    IncompatibleUsage,
}

impl ChainError {
    /// go's `err.Error()`.
    pub fn text(&self) -> String {
        match self {
            Self::Unknown(None) => "x509: certificate signed by unknown authority".to_string(),
            Self::Unknown(Some((why, who))) => format!(
                "x509: certificate signed by unknown authority (possibly because of {why:?} while trying to verify candidate authority certificate {who:?})"
            ),
            Self::IncompatibleUsage => {
                "x509: certificate specifies an incompatible key usage".to_string()
            }
        }
    }
}

/// The common name of `subject` (go's `Subject.CommonName`), else go's
/// `Subject.String()` is not reproduced: an empty name.
fn common_name(subject: &[u8]) -> String {
    // Name ::= SEQUENCE OF RDN (SET OF AttributeTypeAndValue)
    let Some((_, mut rdns, _)) = tlv(subject) else {
        return String::new();
    };
    while !rdns.is_empty() {
        let Some((_, set, after)) = tlv(rdns) else {
            break;
        };
        rdns = after;
        let mut attrs = set;
        while !attrs.is_empty() {
            let Some((_, attr, after)) = tlv(attrs) else {
                break;
            };
            attrs = after;
            if let Some((0x06, oid, rest)) = tlv(attr) {
                if oid == [0x55, 0x04, 0x03] {
                    if let Some((_, v, _)) = tlv(rest) {
                        return String::from_utf8_lossy(v).into_owned();
                    }
                }
            }
        }
    }
    String::new()
}

/// go's `CheckSignatureFrom`: the failure's text, or `Ok`.
fn check_signature_from(
    c: &Cert<'_>,
    parent: &Cert<'_>,
    algs: &rustls::crypto::WebPkiSupportedAlgorithms,
) -> Result<(), String> {
    let violation = "x509: invalid signature: parent certificate cannot sign this kind of certificate";
    if (parent.version3 && !parent.bc_valid) || (parent.bc_valid && !parent.is_ca) {
        return Err(violation.to_string());
    }
    if parent.key_usage != 0 && parent.key_usage & KEY_CERT_SIGN == 0 {
        return Err(violation.to_string());
    }
    // the provider's identifiers are the `AlgorithmIdentifier` contents or
    // the whole element, depending on the version
    let same = |id: &[u8], der: &[u8]| {
        id == der || tlv(der).is_some_and(|(_, content, _)| id == content)
    };
    let alg = algs.all.iter().find(|a| {
        same(a.signature_alg_id().as_ref(), c.sig_alg)
            && same(a.public_key_alg_id().as_ref(), parent.spki_alg)
    });
    let Some(alg) = alg else {
        return Err("x509: cannot verify signature: algorithm unimplemented".to_string());
    };
    alg.verify_signature(parent.public_key, c.tbs, c.signature)
        .map_err(|_| {
            // go's texts by public key algorithm
            const ECDSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
            const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
            let alg_oid = tlv(parent.spki_alg).and_then(|(_, b, _)| tlv(b)).map(|(_, o, _)| o);
            match alg_oid {
                Some(o) if o == ECDSA => "x509: ECDSA verification failure".to_string(),
                Some(o) if o == RSA => "crypto/rsa: verification error".to_string(),
                _ => "x509: signature verification failure".to_string(),
            }
        })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Leaf,
    Intermediate,
    Root,
}

/// go's `isValid`: the period, the CA flag, the path length, and what this
/// module cannot judge (refused).
fn is_valid(c: &Cert<'_>, kind: Kind, below: usize, now: i64) -> Result<(), String> {
    if c.unhandled_critical {
        return Err("x509: unhandled critical extension".to_string());
    }
    if let Some(e) = validity_error(
        &crate::x509_leaf::Leaf {
            not_before: c.not_before,
            not_after: c.not_after,
            ..Default::default()
        },
        now,
    ) {
        return Err(e);
    }
    if kind != Kind::Leaf && c.has_name_constraints {
        return Err("x509: name constraints are not supported".to_string());
    }
    if kind == Kind::Intermediate && !(c.bc_valid && c.is_ca) {
        return Err("x509: certificate is not authorized to sign other certificates".to_string());
    }
    if let Some(max) = c.max_path_len {
        // `len(currentChain) - 1`: the chain below this certificate, less its
        // leaf
        if (below.saturating_sub(1)) as u64 > max && below > 0 {
            return Err("x509: too many intermediates for path length constraint".to_string());
        }
    }
    Ok(())
}

/// Every chain from `chain`'s last certificate to a root.
#[allow(clippy::too_many_arguments)]
fn build<'a>(
    chain: &mut Vec<&'a Cert<'a>>,
    roots: &'a [Cert<'a>],
    inters: &'a [Cert<'a>],
    now: i64,
    algs: &rustls::crypto::WebPkiSupportedAlgorithms,
    hint: &mut Option<(String, String)>,
    out: &mut Vec<Vec<&'a Cert<'a>>>,
) {
    let cur = *chain.last().expect("a chain has its leaf");
    if chain.len() > 100 {
        return;
    }
    for (kind, pool) in [(Kind::Root, roots), (Kind::Intermediate, inters)] {
        for cand in pool.iter().filter(|p| p.subject == cur.issuer) {
            if chain.iter().any(|c| c.der == cand.der) {
                continue;
            }
            let fail = |e: String, hint: &mut Option<(String, String)>| {
                if hint.is_none() {
                    *hint = Some((e, common_name(cand.subject)));
                }
            };
            if let Err(e) = check_signature_from(cur, cand, algs) {
                fail(e, hint);
                continue;
            }
            if let Err(e) = is_valid(cand, kind, chain.len(), now) {
                fail(e, hint);
                continue;
            }
            chain.push(cand);
            if kind == Kind::Root {
                out.push(chain.clone());
            } else {
                build(chain, roots, inters, now, algs, hint, out);
            }
            chain.pop();
        }
    }
}

/// go's `checkChainForKeyUsage` for a `ServerAuth` request.
fn chain_allows_server_auth(chain: &[&Cert<'_>]) -> bool {
    chain.iter().all(|c| match &c.eku {
        None => true,
        Some(list) if list.is_empty() => true,
        Some(list) => list.iter().any(|o| *o == EKU_SERVER_AUTH || *o == EKU_ANY),
    })
}

/// go's `Verify` of a leaf that is a certificate authority, after the
/// period and the name were checked: `Ok` when a chain to one of `roots`
/// exists whose certificates all allow server authentication.
pub fn verify_ca_leaf(
    leaf: &[u8],
    intermediates: &[&[u8]],
    roots: &[&[u8]],
    now: i64,
    algs: &rustls::crypto::WebPkiSupportedAlgorithms,
) -> Result<(), ChainError> {
    let unknown = || ChainError::Unknown(None);
    let leaf_cert = parse(leaf).ok_or_else(unknown)?;
    if is_valid(&leaf_cert, Kind::Leaf, 0, now).is_err() {
        return Err(unknown());
    }
    // certificates that do not parse are not candidates
    let roots: Vec<Cert<'_>> = roots.iter().filter_map(|d| parse(d)).collect();
    let inters: Vec<Cert<'_>> = intermediates.iter().filter_map(|d| parse(d)).collect();
    let mut chains: Vec<Vec<&Cert<'_>>> = Vec::new();
    let mut hint = None;
    if roots.iter().any(|r| r.der == leaf) {
        // go: a leaf that is a root is a chain of its own
        chains.push(vec![&leaf_cert]);
    } else {
        let mut chain = vec![&leaf_cert];
        build(&mut chain, &roots, &inters, now, algs, &mut hint, &mut chains);
    }
    if chains.is_empty() {
        return Err(ChainError::Unknown(hint));
    }
    if chains.iter().any(|c| chain_allows_server_auth(c)) {
        Ok(())
    } else {
        Err(ChainError::IncompatibleUsage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_texts_like_go() {
        assert_eq!(
            ChainError::Unknown(None).text(),
            "x509: certificate signed by unknown authority"
        );
        assert_eq!(
            ChainError::Unknown(Some(("x509: ECDSA verification failure".into(), "ca".into())))
                .text(),
            "x509: certificate signed by unknown authority (possibly because of \"x509: ECDSA verification failure\" while trying to verify candidate authority certificate \"ca\")"
        );
        assert_eq!(
            ChainError::IncompatibleUsage.text(),
            "x509: certificate specifies an incompatible key usage"
        );
    }

    #[test]
    fn garbage_is_refused() {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let algs = provider.signature_verification_algorithms;
        assert_eq!(
            verify_ca_leaf(b"nope", &[], &[], 0, &algs),
            Err(ChainError::Unknown(None))
        );
    }
}
