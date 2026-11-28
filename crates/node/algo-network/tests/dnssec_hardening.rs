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

//! Offline DNSSEC attack cases for the validator algod-rust delegates to
//! (`hickory-resolver` with `validate = true`, i.e. hickory's
//! `DnssecDnsHandle`), ported from go-algorand v5.1.1's hardening of
//! `tools/network/dnssec` (#6770, #6783; issue #2554). go validates with its own
//! code over a `TrustQuerier`; here the same scenarios are served by a mock
//! `DnsHandle` holding freshly signed zones (`.` and `test.`, KSK + ZSK each, the
//! root KSK as the only trust anchor) and hickory's validator must reject every
//! attack that go's `dnssec_test.go` rejects, and accept the positive controls.
//! Every attack test first runs its scenario unmodified to prove the harness
//! produces answers hickory accepts.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures_util::stream::{self, Stream, StreamExt};
use hickory_resolver::net::dnssec::DnssecDnsHandle;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::DnsHandle;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::dnssec::crypto::EcdsaSigningKey;
use hickory_resolver::proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, RRSIG};
use hickory_resolver::proto::dnssec::{
    Algorithm, DigestType, DnssecSigner, PublicKey, SigningKey, TrustAnchors,
};
use hickory_resolver::proto::op::{
    DnsRequest, DnsRequestOptions, DnsResponse, Message, MessageType, OpCode, Query,
};
use hickory_resolver::proto::rr::rdata::{A, AAAA, TXT};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
use time::OffsetDateTime;

type Key = (Name, RecordType);

struct ZoneKey {
    signer: DnssecSigner,
    dnskey: DNSKEY,
}

fn ecdsa_key(zone: &Name, sep: bool) -> ZoneKey {
    let pkcs8 = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
    let key = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256).unwrap();
    let dnskey = DNSKEY::new(true, sep, false, key.to_public_key().unwrap());
    ZoneKey {
        signer: DnssecSigner::new(
            dnskey.clone(),
            Box::new(key),
            zone.clone(),
            std::time::Duration::from_secs(3600),
        ),
        dnskey,
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc() - time::Duration::minutes(5)
}

/// Sign `records` (one RRset) with `signer` and return the records plus the RRSIG.
fn signed(records: Vec<Record>, signer: &DnssecSigner) -> Vec<Record> {
    let first = &records[0];
    let mut set = RecordSet::new(first.name.clone(), first.record_type(), 1);
    for r in &records {
        set.insert(r.clone(), 1);
    }
    let rrsig = RRSIG::from_rrset(&set, DNSClass::IN, now(), signer).unwrap();
    let mut sig = Record::from_rdata(
        first.name.clone(),
        first.ttl,
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
    );
    sig.dns_class = DNSClass::IN;
    let mut out = records;
    out.push(sig);
    out
}

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

#[allow(deprecated)]
fn txt(owner: &str, text: &str) -> Record {
    Record::from_rdata(
        name(owner),
        3600,
        RData::TXT(TXT::new(vec![text.to_string()])),
    )
}

fn a_rec(owner: &str, ip: [u8; 4]) -> Record {
    Record::from_rdata(
        name(owner),
        3600,
        RData::A(A::from(std::net::Ipv4Addr::from(ip))),
    )
}

fn aaaa_rec(owner: &str, ip: std::net::Ipv6Addr) -> Record {
    Record::from_rdata(name(owner), 3600, RData::AAAA(AAAA::from(ip)))
}

/// The mock authoritative side: signed RRsets by (owner, type), plus the
/// substitutions an attacker applies.
#[derive(Clone, Default)]
struct World {
    rrsets: Arc<Mutex<HashMap<Key, Vec<Record>>>>,
    /// (queried name, type) -> name whose RRset is answered instead
    substitute: Arc<Mutex<HashMap<Key, Name>>>,
    /// records appended to the answer of (queried name, type)
    extra: Arc<Mutex<HashMap<Key, Vec<Record>>>>,
    root_ksk: Arc<Mutex<Option<DNSKEY>>>,
}

impl World {
    fn put(&self, owner: &str, rtype: RecordType, records: Vec<Record>) {
        self.rrsets
            .lock()
            .unwrap()
            .insert((name(owner), rtype), records);
    }

    /// Add a zone with a fresh KSK and ZSK: DNSKEY RRset signed by the KSK, DS in
    /// `parent` signed by `parent_zsk` (the root's DS is the trust anchor).
    fn add_zone(&self, zone: &str, parent: Option<(&str, &DnssecSigner)>) -> ZoneKey {
        let zname = name(zone);
        let ksk = ecdsa_key(&zname, true);
        let zsk = ecdsa_key(&zname, false);
        let keys = vec![
            Record::from_rdata(
                zname.clone(),
                3600,
                RData::DNSSEC(DNSSECRData::DNSKEY(ksk.dnskey.clone())),
            ),
            Record::from_rdata(
                zname.clone(),
                3600,
                RData::DNSSEC(DNSSECRData::DNSKEY(zsk.dnskey.clone())),
            ),
        ];
        self.put(zone, RecordType::DNSKEY, signed(keys, &ksk.signer));
        match parent {
            None => *self.root_ksk.lock().unwrap() = Some(ksk.dnskey.clone()),
            Some((_, parent_zsk)) => {
                let digest = ksk.dnskey.to_digest(&zname, DigestType::SHA256).unwrap();
                let ds = DS::new(
                    ksk.dnskey.calculate_key_tag().unwrap(),
                    Algorithm::ECDSAP256SHA256,
                    DigestType::SHA256,
                    digest.as_ref().to_vec(),
                );
                let ds_rec =
                    Record::from_rdata(zname.clone(), 3600, RData::DNSSEC(DNSSECRData::DS(ds)));
                self.put(zone, RecordType::DS, signed(vec![ds_rec], parent_zsk));
            }
        }
        // the zone's ZSK is returned: it signs the zone's data (and child DS)
        ZoneKey {
            signer: zsk.signer,
            dnskey: zsk.dnskey,
        }
    }

    fn handle(&self) -> DnssecDnsHandle<MockHandle> {
        let mut anchors = TrustAnchors::empty();
        let root = self
            .root_ksk
            .lock()
            .unwrap()
            .clone()
            .expect("root zone added");
        anchors.insert(root.public_key());
        DnssecDnsHandle::with_trust_anchor(
            MockHandle {
                world: self.clone(),
            },
            Arc::new(anchors),
        )
    }
}

#[derive(Clone)]
struct MockHandle {
    world: World,
}

impl DnsHandle for MockHandle {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let (message, _) = request.into_parts();
        let query = message.queries.first().cloned().expect("a query");
        let query_name = query.name().clone();
        let mut owner = query.name().clone();
        let qtype = query.query_type();
        if let Some(n) = self
            .world
            .substitute
            .lock()
            .unwrap()
            .get(&(owner.clone(), qtype))
        {
            owner = n.clone();
        }
        let mut response = Message::response(message.metadata.id, OpCode::Query);
        response.metadata.message_type = MessageType::Response;
        response.add_query(query);
        if let Some(records) = self.world.rrsets.lock().unwrap().get(&(owner, qtype)) {
            response.add_answers(records.clone());
        }
        if let Some(extra) = self.world.extra.lock().unwrap().get(&(query_name, qtype)) {
            response.add_answers(extra.clone());
        }
        let resp = DnsResponse::from_message(response).unwrap();
        Box::pin(stream::once(async move { Ok(resp) }))
    }

    fn is_using_edns(&self) -> bool {
        true
    }
}

/// `Ok(records of the type that came back Secure)`; an error or no secure
/// record of the requested type is a rejection.
async fn secure_answers(
    world: &World,
    owner: &str,
    rtype: RecordType,
) -> Result<Vec<Record>, String> {
    let handle = world.handle();
    let query = Query::query(name(owner), rtype);
    let mut options = DnsRequestOptions::default();
    options.use_edns = true;
    let mut responses = handle.lookup(query, options);
    let mut secure = Vec::new();
    while let Some(r) = responses.next().await {
        let resp = r.map_err(|e| e.to_string())?;
        for rec in resp.answers.iter() {
            if rec.record_type() == rtype && rec.proof.is_secure() {
                secure.push(rec.clone());
            }
        }
    }
    if secure.is_empty() {
        Err("no secure answer".to_string())
    } else {
        Ok(secure)
    }
}

/// `.` and `test.` signed with fresh keys; returns the world and test.'s ZSK.
fn signed_world() -> (World, ZoneKey, ZoneKey) {
    let w = World::default();
    let root_zsk = w.add_zone(".", None);
    // the root DNSKEY RRset is signed by the root KSK; the DS of test. by its ZSK
    let test_zsk = w.add_zone("test.", Some((".", &root_zsk.signer)));
    (w, root_zsk, test_zsk)
}

/// Publish `zone`: `keys` as its DNSKEY RRset signed by `dnskey_signer`, and, for
/// a child zone, the DS of `ds_key` signed by the parent's signer.
fn publish(
    w: &World,
    zone: &str,
    parent: Option<&DnssecSigner>,
    keys: &[DNSKEY],
    dnskey_signer: &DnssecSigner,
    ds_key: &DNSKEY,
) {
    let zname = name(zone);
    let records = keys
        .iter()
        .map(|k| {
            Record::from_rdata(
                zname.clone(),
                3600,
                RData::DNSSEC(DNSSECRData::DNSKEY(k.clone())),
            )
        })
        .collect();
    w.put(zone, RecordType::DNSKEY, signed(records, dnskey_signer));
    if let Some(parent) = parent {
        publish_ds(w, zone, name(zone), parent, ds_key);
    }
}

/// Publish the DS of `key` (digest over `key_owner`) at `ds_owner`.
fn publish_ds(w: &World, ds_owner: &str, key_owner: Name, parent: &DnssecSigner, key: &DNSKEY) {
    let digest = key.to_digest(&key_owner, DigestType::SHA256).unwrap();
    let ds = DS::new(
        key.calculate_key_tag().unwrap(),
        key.public_key().algorithm(),
        DigestType::SHA256,
        digest.as_ref().to_vec(),
    );
    let rec = Record::from_rdata(name(ds_owner), 3600, RData::DNSSEC(DNSSECRData::DS(ds)));
    w.put(ds_owner, RecordType::DS, signed(vec![rec], parent));
}

fn put_signed(w: &World, owner: &str, rtype: RecordType, rec: Record, signer: &DnssecSigner) {
    w.put(owner, rtype, signed(vec![rec], signer));
}

fn substitute(w: &World, queried: &str, rtype: RecordType, answered: &str) {
    w.substitute
        .lock()
        .unwrap()
        .insert((name(queried), rtype), name(answered));
}

fn assert_rejected(got: Result<Vec<Record>, String>, what: &str) {
    assert!(got.is_err(), "{what}: accepted {got:?}");
}

#[tokio::test]
async fn positive_control_signed_records_are_secure() {
    let (w, _root, test) = signed_world();
    put_signed(
        &w,
        "wanted.test.",
        RecordType::TXT,
        txt("wanted.test.", "ok"),
        &test.signer,
    );
    put_signed(
        &w,
        "v6only.test.",
        RecordType::AAAA,
        aaaa_rec("v6only.test.", "2001:db8::1".parse().unwrap()),
        &test.signer,
    );
    put_signed(
        &w,
        "www.test.",
        RecordType::A,
        a_rec("www.test.", [1, 2, 3, 4]),
        &test.signer,
    );
    for (n, t) in [
        ("wanted.test.", RecordType::TXT),
        ("v6only.test.", RecordType::AAAA),
        ("www.test.", RecordType::A),
    ] {
        let got = secure_answers(&w, n, t).await;
        assert!(got.is_ok(), "{n} {t}: {got:?}");
    }
}

/// go `TestLookupRejectsSignedRRSetFromAnotherName` /
/// `TestLookupIPAddrRejectsSignedRRSetFromAnotherName`: a validly signed RRset
/// of `foreign.test.` served for the query `wanted.test.` is not an answer.
#[tokio::test]
async fn rrset_signed_for_another_name_is_rejected() {
    for (rtype, record) in [
        (RecordType::TXT, txt("foreign.test.", "foreign")),
        (RecordType::A, a_rec("foreign.test.", [6, 6, 6, 6])),
    ] {
        let (w, _root, test) = signed_world();
        put_signed(&w, "foreign.test.", rtype, record, &test.signer);
        // control: asking for the foreign name itself works
        assert!(secure_answers(&w, "foreign.test.", rtype).await.is_ok());
        substitute(&w, "wanted.test.", rtype, "foreign.test.");
        assert_rejected(
            secure_answers(&w, "wanted.test.", rtype).await,
            "foreign rrset",
        );
    }
}

/// go `TestLookupRejectsSignerOutsideOwnerZone`: `algorand.test.` signed by
/// the keys of the sibling zone `rand.test.`.
#[tokio::test]
async fn signer_outside_the_owner_zone_is_rejected() {
    let (w, _root, test) = signed_world();
    let rand = w.add_zone("rand.test.", Some(("test.", &test.signer)));
    put_signed(
        &w,
        "algorand.test.",
        RecordType::TXT,
        txt("algorand.test.", "attacker controlled"),
        &rand.signer,
    );
    // control: the sibling zone's own data is fine
    put_signed(
        &w,
        "own.rand.test.",
        RecordType::TXT,
        txt("own.rand.test.", "ok"),
        &rand.signer,
    );
    assert!(secure_answers(&w, "own.rand.test.", RecordType::TXT)
        .await
        .is_ok());
    assert_rejected(
        secure_answers(&w, "algorand.test.", RecordType::TXT).await,
        "foreign signer",
    );
}

/// go `TestLookupRejectsDSFromAnotherName`: the DS of `attacker.test.` (a
/// genuine, parent-signed RRset that carries the digest of victim.test.'s KSK)
/// served for the query `victim.test. DS`.
#[tokio::test]
async fn ds_from_another_name_is_rejected() {
    let (w, _root, test) = signed_world();
    let victim_ksk = ecdsa_key(&name("victim.test."), true);
    let victim_zsk = ecdsa_key(&name("victim.test."), false);
    publish(
        &w,
        "victim.test.",
        None,
        &[victim_ksk.dnskey.clone(), victim_zsk.dnskey.clone()],
        &victim_ksk.signer,
        &victim_ksk.dnskey,
    );
    put_signed(
        &w,
        "victim.test.",
        RecordType::TXT,
        txt("victim.test.", "victim"),
        &victim_zsk.signer,
    );
    // control: with the real DS the victim zone validates
    publish_ds(
        &w,
        "victim.test.",
        name("victim.test."),
        &test.signer,
        &victim_ksk.dnskey,
    );
    assert!(secure_answers(&w, "victim.test.", RecordType::TXT)
        .await
        .is_ok());
    // attack: the DS query for victim.test. is answered with attacker.test.'s DS
    publish_ds(
        &w,
        "attacker.test.",
        name("victim.test."),
        &test.signer,
        &victim_ksk.dnskey,
    );
    w.rrsets
        .lock()
        .unwrap()
        .remove(&(name("victim.test."), RecordType::DS));
    substitute(&w, "victim.test.", RecordType::DS, "attacker.test.");
    assert_rejected(
        secure_answers(&w, "victim.test.", RecordType::TXT).await,
        "ds of another name",
    );
}

/// go `TestLookupRejectsDNSKEYFromAnotherName`: the validly signed DNSKEY RRset
/// of `other.test.` served for `test. DNSKEY`.
#[tokio::test]
async fn dnskey_from_another_name_is_rejected() {
    let (w, _root, test) = signed_world();
    w.add_zone("other.test.", Some(("test.", &test.signer)));
    put_signed(
        &w,
        "www.test.",
        RecordType::TXT,
        txt("www.test.", "www"),
        &test.signer,
    );
    assert!(secure_answers(&w, "www.test.", RecordType::TXT)
        .await
        .is_ok());
    substitute(&w, "test.", RecordType::DNSKEY, "other.test.");
    assert_rejected(
        secure_answers(&w, "www.test.", RecordType::TXT).await,
        "dnskey of another name",
    );
}

/// go `TestLookupRejectsUnprovedWildcardExpansion`: the `*.test.` RRset and its
/// RRSIG re-labelled as `wanted.test.` without a proof that no closer name
/// exists. (go rejects every wildcard answer; hickory accepts a wildcard answer
/// only with an NSEC/NSEC3 proof, which this mock never serves.)
#[tokio::test]
async fn unproved_wildcard_expansion_is_rejected() {
    let (w, _root, test) = signed_world();
    let wildcard = signed(vec![txt("*.test.", "wildcard")], &test.signer);
    // control: the wildcard RRset itself, asked for under its own name, is secure
    w.put("*.test.", RecordType::TXT, wildcard.clone());
    assert!(secure_answers(&w, "*.test.", RecordType::TXT).await.is_ok());
    let expanded: Vec<Record> = wildcard
        .into_iter()
        .map(|mut r| {
            r.name = name("wanted.test.");
            r
        })
        .collect();
    w.put("wanted.test.", RecordType::TXT, expanded);
    assert_rejected(
        secure_answers(&w, "wanted.test.", RecordType::TXT).await,
        "unproved wildcard",
    );
}

/// go `TestLookupCombinedSigningKey`: one key with ZONE|SEP signs the DNSKEY
/// RRset and the data (a CSK). A revoked key may stay published during a
/// rollover but must not authenticate data.
#[tokio::test]
async fn combined_signing_key_validates_and_a_revoked_key_does_not() {
    let w = World::default();
    let root_zsk = w.add_zone(".", None);
    let csk = ecdsa_key(&name("test."), true);
    publish(
        &w,
        "test.",
        Some(&root_zsk.signer),
        std::slice::from_ref(&csk.dnskey),
        &csk.signer,
        &csk.dnskey,
    );
    put_signed(
        &w,
        "www.test.",
        RecordType::A,
        a_rec("www.test.", [1, 2, 3, 4]),
        &csk.signer,
    );
    assert!(secure_answers(&w, "www.test.", RecordType::A).await.is_ok());

    // a revoked key published next to the CSK changes nothing
    let pkcs8 = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
    let revoked_sk = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256).unwrap();
    let revoked_key = DNSKEY::new(true, true, true, revoked_sk.to_public_key().unwrap());
    publish(
        &w,
        "test.",
        None,
        &[csk.dnskey.clone(), revoked_key.clone()],
        &csk.signer,
        &csk.dnskey,
    );
    assert!(secure_answers(&w, "www.test.", RecordType::A).await.is_ok());

    // data signed by the revoked key is rejected
    let revoked_signer = DnssecSigner::new(
        revoked_key,
        Box::new(revoked_sk),
        name("test."),
        std::time::Duration::from_secs(3600),
    );
    put_signed(
        &w,
        "www.test.",
        RecordType::A,
        a_rec("www.test.", [1, 2, 3, 4]),
        &revoked_signer,
    );
    assert_rejected(
        secure_answers(&w, "www.test.", RecordType::A).await,
        "revoked key",
    );
}

/// A DNSKEY with the key tag of `target` but other key material (go's
/// `sameTagKey`): a decoy that cannot verify anything.
fn same_tag_decoy(target: &DNSKEY) -> DNSKEY {
    let tag = target.calculate_key_tag().unwrap();
    let flags = if target.secure_entry_point() {
        257
    } else {
        256
    };
    for _ in 0..2_000_000 {
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
        let key = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256).unwrap();
        let cand = DNSKEY::with_flags(flags, key.to_public_key().unwrap());
        if cand.calculate_key_tag().unwrap() == tag
            && cand.public_key().public_bytes() != target.public_key().public_bytes()
        {
            return cand;
        }
    }
    panic!("no colliding key found");
}

/// go `TestLookupCollidingDNSKEYTags`: decoy keys with the key tags of the
/// zone's real KSK and ZSK are published in the DNSKEY RRset.
#[tokio::test]
async fn colliding_dnskey_tags_do_not_break_validation() {
    let w = World::default();
    let root_zsk = w.add_zone(".", None);
    let ksk = ecdsa_key(&name("test."), true);
    let zsk = ecdsa_key(&name("test."), false);
    let decoy_zsk = same_tag_decoy(&zsk.dnskey);
    let decoy_ksk = same_tag_decoy(&ksk.dnskey);
    publish(
        &w,
        "test.",
        Some(&root_zsk.signer),
        &[decoy_zsk, zsk.dnskey.clone(), ksk.dnskey.clone(), decoy_ksk],
        &ksk.signer,
        &ksk.dnskey,
    );
    put_signed(
        &w,
        "www.test.",
        RecordType::A,
        a_rec("www.test.", [1, 2, 3, 4]),
        &zsk.signer,
    );
    assert!(secure_answers(&w, "www.test.", RecordType::A).await.is_ok());
}

/// go `TestMakeTrustedZoneIgnoresRSAMD5Key`: an RSAMD5 DNSKEY (algorithm 1,
/// unusable) in the zone's DNSKEY RRset does not stop the zone from validating.
#[tokio::test]
#[allow(deprecated)]
async fn rsamd5_key_in_the_dnskey_set_is_ignored() {
    let w = World::default();
    let root_zsk = w.add_zone(".", None);
    let ksk = ecdsa_key(&name("test."), true);
    let zsk = ecdsa_key(&name("test."), false);
    let md5 = DNSKEY::with_flags(
        256,
        hickory_resolver::proto::dnssec::PublicKeyBuf::new(vec![1, 2], Algorithm::RSAMD5),
    );
    publish(
        &w,
        "test.",
        Some(&root_zsk.signer),
        &[ksk.dnskey.clone(), zsk.dnskey.clone(), md5],
        &ksk.signer,
        &ksk.dnskey,
    );
    put_signed(
        &w,
        "www.test.",
        RecordType::A,
        a_rec("www.test.", [1, 2, 3, 4]),
        &zsk.signer,
    );
    assert!(secure_answers(&w, "www.test.", RecordType::A).await.is_ok());
}

/// go `TestSelectRRSet` / `TestLookupRejectsSignedRRSetFromAnotherName`: an
/// answer may carry a genuinely signed RRset of *another* name next to the
/// queried one. hickory's `CachingClient` returns the whole answer section in
/// that case (it filters by owner only to follow a CNAME), so the consumers
/// (`srv_resolver::answers_for_query`, `dnsaddr::answers_for_query`) must select
/// the records of the queried name themselves. This test pins the hickory
/// behaviour that makes that necessary.
#[tokio::test]
async fn hickory_returns_foreign_records_so_consumers_must_filter() {
    use hickory_resolver::caching_client::CachingClient;
    let (w, _root, test) = signed_world();
    let wanted = signed(vec![txt("wanted.test.", "wanted")], &test.signer);
    let foreign = signed(vec![txt("foreign.test.", "foreign")], &test.signer);
    w.put("wanted.test.", RecordType::TXT, wanted.clone());
    // the response to `wanted.test. TXT` also carries foreign.test.'s signed RRset
    w.extra
        .lock()
        .unwrap()
        .insert((name("wanted.test."), RecordType::TXT), foreign);
    let client = CachingClient::new(16, w.handle(), false);
    let mut options = DnsRequestOptions::default();
    options.use_edns = true;
    // query-name case does not matter (go: "ignores query name case")
    for qname in ["wanted.test.", "WANTED.Test."] {
        let lookup = client
            .lookup(Query::query(name(qname), RecordType::TXT), options)
            .await
            .unwrap_or_else(|e| panic!("{qname}: {e}"));
        let owners: Vec<String> = lookup
            .answers()
            .iter()
            .filter(|r| r.record_type() == RecordType::TXT)
            .map(|r| r.name.to_ascii().to_lowercase())
            .collect();
        assert_eq!(
            owners,
            vec!["wanted.test.", "foreign.test."],
            "{qname}: hickory now filters by owner; the consumers' own filter is redundant"
        );
    }
}
