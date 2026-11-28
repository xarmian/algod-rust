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

//! `dnsaddr` multiaddr-via-DNS resolution for libp2p bootstrap entries.
//!
//! Mirrors go-algorand's `network/p2p/dnsaddr/resolve.go`
//! (`MultiaddrsFromResolver` / `Iterate`): a `/dnsaddr/<domain>` multiaddr
//! is resolved by querying the `_dnsaddr.<domain>` TXT record set; each TXT
//! value has the form `dnsaddr=<multiaddr>`. A resolved multiaddr whose
//! first protocol is itself `/dnsaddr/<domain>` is followed recursively
//! (bounded by [`MAX_HOPS`], matching go's `maxHops = 25`) so a nested
//! dnsaddr tree is fully expanded into concrete multiaddrs.
//!
//! This is distinct from the existing WS-gossip SRV/phonebook bootstrap in
//! `algo-network` (`_algobootstrap._tcp.<domain>` SRV records resolved by
//! [`HickorySrvResolver`](https://docs.rs/algo-network) into `host:port`
//! pairs): Algorand's libp2p bootstrap DNS records resolve to full libp2p
//! multiaddrs (`/ip4/.../tcp/.../p2p/<peer-id>`) via TXT, not SRV.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use hickory_resolver::config::{ResolverConfig, ServerGroup, CLOUDFLARE, GOOGLE};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError as ResolveError;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use thiserror::Error;
use tracing::{debug, warn};

/// Matches go's `Iterate`'s `maxHops = 25` — an upper bound on recursive
/// `dnsaddr` chasing, to guard against a circular DNS configuration.
const MAX_HOPS: usize = 25;

const DNSADDR_TXT_PREFIX: &str = "dnsaddr=";

/// Errors produced while resolving a `dnsaddr` bootstrap entry.
#[derive(Debug, Error)]
pub enum DnsaddrError {
    /// Recursive `dnsaddr` resolution exceeded [`MAX_HOPS`] — likely a
    /// circular reference (go: `Iterate`'s "max hops reached" error).
    #[error("dnsaddr resolution for {0} exceeded {MAX_HOPS} hops (possible circular reference)")]
    TooManyHops(String),

    /// All resolver attempts (system, fallback, default) failed.
    #[error("DNS TXT lookup for _dnsaddr.{domain} failed: system({system}), fallback({fallback}), default({default})")]
    AllResolversFailed {
        /// Domain that failed to resolve.
        domain: String,
        /// Error from the system resolver.
        system: String,
        /// Error from the fallback resolver (or "not configured").
        fallback: String,
        /// Error from the default resolver.
        default: String,
    },
}

/// Trait abstracting `_dnsaddr.<domain>` TXT lookups, for testability.
///
/// Returns the raw TXT record values (still `dnsaddr=`-prefixed) rather
/// than parsed [`Multiaddr`]s — parsing/prefix-stripping happens once in
/// [`resolve_multiaddrs`] regardless of resolver implementation.
pub trait DnsaddrResolver: Send + Sync {
    /// Look up TXT records for `_dnsaddr.<domain>`.
    fn resolve_txt(
        &self,
        domain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + '_>>;
}

/// Production [`DnsaddrResolver`] backed by hickory-resolver, following the
/// same system -> fallback -> default resolver chain as
/// `algo-network`'s [`HickorySrvResolver`](https://docs.rs/algo-network)
/// (mirroring go's `MultiaddrDNSResolveController`).
pub struct HickoryDnsaddrResolver {
    system: HickoryStage,
    /// Only with a configured fallback address (go: `fallbackDNSResolverAddress != ""`).
    fallback: Option<HickoryStage>,
    default: HickoryStage,
}

impl HickoryDnsaddrResolver {
    /// Create a new resolver. `fallback_dns` is an optional IP address used
    /// as a fallback when the system resolver fails.
    pub fn new(fallback_dns: Option<String>) -> Self {
        Self {
            system: HickoryStage::new(|| Self::system_resolver().map_err(|e| e.to_string())),
            fallback: fallback_dns.map(|addr| {
                HickoryStage::new(move || {
                    Self::fallback_resolver(&addr)
                        .ok_or_else(|| "fallback address could not be parsed".to_string())
                })
            }),
            default: HickoryStage::new(|| Ok(Self::default_resolver())),
        }
    }

    fn build_resolver(config: ResolverConfig) -> TokioResolver {
        let provider = TokioRuntimeProvider::default();
        let mut builder = TokioResolver::builder_with_config(config, provider);
        let opts = builder.options_mut();
        opts.validate = true;
        opts.try_tcp_on_error = true;
        builder
            .build()
            .expect("resolver build only fails on invalid TLS/QUIC config; ours is plain UDP/TCP")
    }

    fn system_resolver() -> Result<TokioResolver, ResolveError> {
        let mut builder = TokioResolver::builder_tokio()?;
        let opts = builder.options_mut();
        opts.validate = true;
        opts.try_tcp_on_error = true;
        builder.build()
    }

    fn fallback_resolver(addr: &str) -> Option<TokioResolver> {
        let ip: IpAddr = addr.parse().ok()?;
        let ips = [ip];
        let group = ServerGroup {
            ips: &ips,
            server_name: "",
            path: "",
        };
        let config = ResolverConfig::udp_and_tcp(&group);
        Some(Self::build_resolver(config))
    }

    fn default_resolver() -> TokioResolver {
        let mut name_servers: Vec<_> = CLOUDFLARE.udp_and_tcp().collect();
        name_servers.extend(GOOGLE.udp_and_tcp());
        let config = ResolverConfig::from_name_servers(name_servers);
        Self::build_resolver(config)
    }

    async fn do_lookup(resolver: &TokioResolver, name: &str) -> Result<Vec<String>, ResolveError> {
        let lookup = resolver.txt_lookup(name).await?;
        let values = answers_for_query(lookup.query(), lookup.answers())
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(txt),
                _ => None,
            })
            .filter_map(|txt| {
                let bytes: Vec<u8> = txt
                    .txt_data
                    .iter()
                    .flat_map(|c| c.iter().copied())
                    .collect();
                String::from_utf8(bytes).ok()
            })
            .collect();
        Ok(values)
    }
}

/// One resolver of the chain: a TXT lookup that either answers or fails with a
/// message. go's `MultiaddrDNSResolveController` hands out one resolver per
/// stage (`Resolver` / `NextResolver`).
pub(crate) trait TxtStage: Send + Sync {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>;
}

/// Try each stage once, in order of preference, starting with the first one:
/// go v5.1.1 `MultiaddrDNSResolveController` starts a new pass through its
/// resolvers for every lookup (`Resolver()` resets the position), so a resolver
/// that failed in an earlier lookup is tried again. Returns the first answer, or
/// every stage's error in order.
pub(crate) async fn lookup_txt_chain(
    name: &str,
    stages: &[&dyn TxtStage],
) -> Result<Vec<String>, Vec<String>> {
    let mut errors = Vec::with_capacity(stages.len());
    for stage in stages {
        match stage.lookup(name).await {
            Ok(values) => return Ok(values),
            Err(e) => errors.push(e),
        }
    }
    Err(errors)
}

/// A hickory resolver that is built on first use and then kept, so its cache
/// (including the DNSSEC trust chain) survives across lookups, as go v5.1.1's
/// controller keeps the resolvers it has created.
struct HickoryStage {
    build: Box<dyn Fn() -> Result<TokioResolver, String> + Send + Sync>,
    resolver: std::sync::Mutex<Option<std::sync::Arc<TokioResolver>>>,
}

impl HickoryStage {
    fn new(build: impl Fn() -> Result<TokioResolver, String> + Send + Sync + 'static) -> Self {
        Self {
            build: Box::new(build),
            resolver: std::sync::Mutex::new(None),
        }
    }

    fn get(&self) -> Result<std::sync::Arc<TokioResolver>, String> {
        let mut guard = self.resolver.lock().expect("resolver mutex poisoned");
        if let Some(r) = guard.as_ref() {
            return Ok(std::sync::Arc::clone(r));
        }
        let r = std::sync::Arc::new((self.build)()?);
        *guard = Some(std::sync::Arc::clone(&r));
        Ok(r)
    }
}

impl TxtStage for HickoryStage {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>> {
        Box::pin(async move {
            let resolver = self.get()?;
            HickoryDnsaddrResolver::do_lookup(&resolver, name)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

impl DnsaddrResolver for HickoryDnsaddrResolver {
    fn resolve_txt(
        &self,
        domain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + '_>> {
        let domain = domain.to_string();
        Box::pin(async move {
            let name = format!("_dnsaddr.{domain}");
            let mut stages: Vec<&dyn TxtStage> = vec![&self.system];
            if let Some(fallback) = &self.fallback {
                stages.push(fallback);
            }
            stages.push(&self.default);
            match lookup_txt_chain(&name, &stages).await {
                Ok(values) => Ok(values),
                Err(errors) => {
                    let system = errors.first().cloned().unwrap_or_default();
                    let default = errors.last().cloned().unwrap_or_default();
                    let fallback = if self.fallback.is_some() {
                        errors.get(1).cloned().unwrap_or_default()
                    } else {
                        "not configured".to_string()
                    };
                    warn!(
                        domain,
                        sys_err = system,
                        fb_err = fallback,
                        default_err = default,
                        "dnsaddr TXT lookup failed"
                    );
                    Err(DnsaddrError::AllResolversFailed {
                        domain,
                        system,
                        fallback,
                        default,
                    }
                    .to_string())
                }
            }
        })
    }
}

fn is_dnsaddr(maddr: &Multiaddr) -> bool {
    matches!(maddr.iter().next(), Some(Protocol::Dnsaddr(_)))
}

fn dnsaddr_domain(maddr: &Multiaddr) -> Option<String> {
    match maddr.iter().next() {
        Some(Protocol::Dnsaddr(domain)) => Some(domain.into_owned()),
        _ => None,
    }
}

/// Resolve all concrete (non-`dnsaddr`) multiaddrs reachable from
/// `/dnsaddr/<domain>`, recursively following any nested `dnsaddr` entries
/// found along the way.
///
/// Go: `dnsaddr.MultiaddrsFromResolver` + `Iterate`. Unlike go's `Iterate`,
/// a single domain's lookup failure does not abort the whole resolution —
/// it is logged and skipped, so one broken hop in a bootstrap list does not
/// take down bootstrap for every other configured domain (the caller,
/// e.g. an `algo-p2p` bootstrap orchestrator with several configured
/// domains, calls this once per top-level domain and merges results).
pub async fn resolve_multiaddrs(domain: &str, resolver: &dyn DnsaddrResolver) -> Vec<Multiaddr> {
    let mut to_resolve = vec![domain.to_string()];
    let mut resolved = Vec::new();
    let mut hops = 0usize;

    while let Some(current) = to_resolve.pop() {
        hops += 1;
        if hops > MAX_HOPS {
            warn!(
                domain,
                hops, "dnsaddr resolution exceeded max hops, stopping"
            );
            break;
        }

        let txts = match resolver.resolve_txt(&current).await {
            Ok(txts) => txts,
            Err(e) => {
                debug!(domain = %current, error = %e, "dnsaddr TXT lookup failed, skipping");
                continue;
            }
        };

        for txt in txts {
            let Some(rest) = txt.strip_prefix(DNSADDR_TXT_PREFIX) else {
                continue;
            };
            let maddr: Multiaddr = match rest.parse() {
                Ok(m) => m,
                Err(e) => {
                    debug!(value = rest, error = %e, "malformed dnsaddr TXT value, skipping");
                    continue;
                }
            };
            if is_dnsaddr(&maddr) {
                if let Some(next_domain) = dnsaddr_domain(&maddr) {
                    to_resolve.push(next_domain);
                }
            } else {
                resolved.push(maddr);
            }
        }
    }

    resolved
}

/// The answer records that belong to `query`: those owned by the queried name
/// and of its class. go v5.1.1 binds every DNSSEC answer to its query
/// (`selectRRSet`, #6783): a response may also carry RRsets of other names
/// (genuinely signed, e.g. replayed from another bootstrap domain), and
/// hickory returns the whole answer section unfiltered when the queried name is
/// present. A CNAME is not followed (go: "rejects a CNAME for a TXT query").
fn answers_for_query<'a>(
    query: &'a hickory_resolver::proto::op::Query,
    answers: &'a [hickory_resolver::proto::rr::Record],
) -> impl Iterator<Item = &'a hickory_resolver::proto::rr::Record> {
    answers
        .iter()
        .filter(move |r| r.dns_class == query.query_class() && r.name == *query.name())
}

#[cfg(test)]
mod tests {

    /// go's dnsaddr resolvers use the same DNSSEC client as the SRV ones: a
    /// 1232-byte EDNS buffer, DO bit, TCP retry (`TestQueryAdvertisesReducedEDNSBuffer`).
    #[test]
    fn dnsaddr_resolvers_validate_with_a_1232_byte_edns_buffer_and_tcp_retry() {
        let resolver = HickoryDnsaddrResolver::default_resolver();
        let opts = resolver.options();
        assert!(opts.validate && opts.edns0 && opts.try_tcp_on_error);
        assert_eq!(opts.edns_payload_len, 1232);
    }

    /// go v5.1.1 `TestSelectRRSet` / `TestLookupRejectsSignedRRSetFromAnotherName`:
    /// a signed TXT RRset of another name carried in the answer is not a dnsaddr
    /// of the queried domain.
    #[test]
    fn answers_for_query_keeps_only_the_queried_name() {
        use hickory_resolver::proto::op::Query;
        use hickory_resolver::proto::rr::rdata::TXT;
        use hickory_resolver::proto::rr::{Name, Record, RecordType};
        #[allow(deprecated)]
        let txt = |owner: &str, text: &str| {
            Record::from_rdata(
                Name::from_ascii(owner).unwrap(),
                60,
                RData::TXT(TXT::new(vec![text.to_string()])),
            )
        };
        let wanted = txt("_dnsaddr.wanted.test.", "dnsaddr=/ip4/1.2.3.4/tcp/1");
        let foreign = txt("_dnsaddr.foreign.test.", "dnsaddr=/ip4/6.6.6.6/tcp/1");
        let answers = vec![foreign.clone(), wanted.clone()];
        for qname in ["_dnsaddr.wanted.test.", "_DNSADDR.Wanted.TEST."] {
            let query = Query::query(Name::from_ascii(qname).unwrap(), RecordType::TXT);
            let kept: Vec<&Record> = answers_for_query(&query, &answers).collect();
            assert_eq!(kept, vec![&wanted], "{qname}");
        }
        let query = Query::query(
            Name::from_ascii("_dnsaddr.wanted.test.").unwrap(),
            RecordType::TXT,
        );
        assert_eq!(answers_for_query(&query, &[foreign]).count(), 0);
    }
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockResolver {
        // domain -> TXT values
        records: Mutex<HashMap<String, Vec<String>>>,
    }

    impl MockResolver {
        fn new(records: HashMap<String, Vec<String>>) -> Self {
            Self {
                records: Mutex::new(records),
            }
        }
    }

    impl DnsaddrResolver for MockResolver {
        fn resolve_txt(
            &self,
            domain: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + '_>> {
            let result = self
                .records
                .lock()
                .unwrap()
                .get(domain)
                .cloned()
                .ok_or_else(|| "NXDOMAIN".to_string());
            Box::pin(async move { result })
        }
    }

    // Go: `TestIsDnsaddr` (`network/p2p/dnsaddr/resolve_test.go`) — direct
    // port of the same table (`is_dnsaddr` is a private fn in this module,
    // so the test module can call it directly rather than only exercising it
    // indirectly through `resolve_multiaddrs`).
    #[test]
    fn is_dnsaddr_table() {
        let cases: &[(&str, bool)] = &[
            ("/dnsaddr/foobar.com", true),
            (
                "/dnsaddr/foobar.com/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
                true,
            ),
            (
                "/dnsaddr/foobar.com/ip4/127.0.0.1/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
                true,
            ),
            ("/dns4/foobar.com", false),
            ("/dns6/foobar.com", false),
            (
                "/dns4/foobar.com/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
                false,
            ),
        ];
        for (addr, expected) in cases {
            let maddr: Multiaddr = addr.parse().expect("valid multiaddr");
            assert_eq!(
                is_dnsaddr(&maddr),
                *expected,
                "is_dnsaddr({addr}) expected {expected}"
            );
        }
    }

    #[tokio::test]
    async fn resolves_concrete_multiaddrs() {
        let peer_id = libp2p::PeerId::random();
        let addr = format!("/ip4/1.2.3.4/tcp/4160/p2p/{peer_id}");
        let mut records = HashMap::new();
        records.insert(
            "example.algorand.network".to_string(),
            vec![format!("dnsaddr={addr}")],
        );
        let resolver = MockResolver::new(records);

        let resolved = resolve_multiaddrs("example.algorand.network", &resolver).await;
        assert_eq!(resolved, vec![addr.parse::<Multiaddr>().unwrap()]);
    }

    #[tokio::test]
    async fn ignores_non_dnsaddr_prefixed_txt_records() {
        let mut records = HashMap::new();
        records.insert(
            "example.algorand.network".to_string(),
            vec!["v=spf1 -all".to_string()],
        );
        let resolver = MockResolver::new(records);

        let resolved = resolve_multiaddrs("example.algorand.network", &resolver).await;
        assert!(resolved.is_empty());
    }

    #[tokio::test]
    async fn follows_nested_dnsaddr_entries_recursively() {
        let peer_id = libp2p::PeerId::random();
        let leaf_addr = format!("/ip4/5.6.7.8/tcp/4160/p2p/{peer_id}");

        let mut records = HashMap::new();
        records.insert(
            "root.algorand.network".to_string(),
            vec!["dnsaddr=/dnsaddr/leaf.algorand.network".to_string()],
        );
        records.insert(
            "leaf.algorand.network".to_string(),
            vec![format!("dnsaddr={leaf_addr}")],
        );
        let resolver = MockResolver::new(records);

        let resolved = resolve_multiaddrs("root.algorand.network", &resolver).await;
        assert_eq!(resolved, vec![leaf_addr.parse::<Multiaddr>().unwrap()]);
    }

    #[tokio::test]
    async fn missing_domain_resolves_to_empty_not_panic() {
        let resolver = MockResolver::new(HashMap::new());
        let resolved = resolve_multiaddrs("nonexistent.invalid", &resolver).await;
        assert!(resolved.is_empty());
    }

    #[tokio::test]
    async fn circular_dnsaddr_chain_terminates_via_max_hops() {
        let mut records = HashMap::new();
        records.insert(
            "a.algorand.network".to_string(),
            vec!["dnsaddr=/dnsaddr/b.algorand.network".to_string()],
        );
        records.insert(
            "b.algorand.network".to_string(),
            vec!["dnsaddr=/dnsaddr/a.algorand.network".to_string()],
        );
        let resolver = MockResolver::new(records);

        // Must terminate (not hang/loop forever) and not panic.
        let resolved = resolve_multiaddrs("a.algorand.network", &resolver).await;
        assert!(resolved.is_empty());
    }

    #[tokio::test]
    async fn malformed_multiaddr_is_skipped_not_fatal() {
        let mut records = HashMap::new();
        records.insert(
            "example.algorand.network".to_string(),
            vec!["dnsaddr=not-a-valid-multiaddr".to_string()],
        );
        let resolver = MockResolver::new(records);

        let resolved = resolve_multiaddrs("example.algorand.network", &resolver).await;
        assert!(resolved.is_empty());
    }

    // -------------------------------------------------------------------
    // go v5.1.1 `network/p2p/dnsaddr/resolveController_test.go`:
    // `TestControllerRecoversAfterOutage`, `TestControllerTriesEachResolverPerLookup`,
    // `TestControllerBackupAfterPrimaryFailure`.
    // -------------------------------------------------------------------

    const TEST_DNSADDR: &str =
        "dnsaddr=/ip4/1.2.3.4/tcp/4190/p2p/12D3KooWSH9L2dT6GYUg2HKXDzNiY3tjH75ibU4yJsWVWGaQRZ2x";

    /// go's `fakeDNS`: answers dnsaddr TXT lookups and counts them; fails while
    /// `down` is set and always for names starting with `_dnsaddr.down.`.
    #[derive(Default)]
    struct FakeStage {
        down: std::sync::atomic::AtomicBool,
        lookups: std::sync::atomic::AtomicUsize,
    }

    impl FakeStage {
        fn set_down(&self, down: bool) {
            self.down.store(down, std::sync::atomic::Ordering::SeqCst);
        }
        fn lookups(&self) -> usize {
            self.lookups.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl TxtStage for FakeStage {
        fn lookup<'a>(
            &'a self,
            name: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>> {
            Box::pin(async move {
                self.lookups
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if self.down.load(std::sync::atomic::Ordering::SeqCst)
                    || name.starts_with("_dnsaddr.down.")
                {
                    return Err("i/o timeout".to_string());
                }
                Ok(vec![TEST_DNSADDR.to_string()])
            })
        }
    }

    async fn chain(stages: &[&FakeStage], domain: &str) -> Result<Vec<String>, Vec<String>> {
        let stages: Vec<&dyn TxtStage> = stages.iter().map(|s| *s as &dyn TxtStage).collect();
        lookup_txt_chain(&format!("_dnsaddr.{domain}"), &stages).await
    }

    /// A lookup after an outage tries the resolvers again instead of failing
    /// because the outage used them all up, and every lookup starts with the
    /// preferred resolver (`TestControllerRecoversAfterOutage` /
    /// `TestControllerTriesEachResolverPerLookup`).
    #[tokio::test]
    async fn every_lookup_starts_a_new_pass_through_the_resolvers() {
        let (a, b) = (FakeStage::default(), FakeStage::default());
        assert!(chain(&[&a, &b], "example.com").await.is_ok());
        assert_eq!((a.lookups(), b.lookups()), (1, 0));

        a.set_down(true);
        b.set_down(true);
        let err = chain(&[&a, &b], "example.com").await.unwrap_err();
        assert_eq!(err, vec!["i/o timeout".to_string(); 2]);
        assert_eq!((a.lookups(), b.lookups()), (2, 1));

        // the outage is over for b only: a is tried first and fails, b answers
        a.set_down(true);
        b.set_down(false);
        assert!(chain(&[&a, &b], "example.com").await.is_ok());
        assert_eq!((a.lookups(), b.lookups()), (3, 2));

        // both recovered: the next lookup starts again with a
        a.set_down(false);
        assert!(chain(&[&a, &b], "example.com").await.is_ok());
        assert_eq!((a.lookups(), b.lookups()), (4, 2));
    }

    /// A failed lookup of the primary bootstrap domain does not prevent the
    /// lookup of the backup domain on the same resolver
    /// (`TestControllerBackupAfterPrimaryFailure`).
    #[tokio::test]
    async fn backup_domain_is_resolved_after_the_primary_failed() {
        let dns = FakeStage::default();
        assert!(chain(&[&dns, &dns], "down.example.com").await.is_err());
        let txts = chain(&[&dns, &dns], "example.com").await.unwrap();
        assert_eq!(txts.len(), 1);
    }

    /// go: "each resolver is created on first use and then reused" (a DNSSEC
    /// resolver keeps its trust chain cache across lookups).
    #[test]
    fn resolvers_are_created_on_first_use_and_then_reused() {
        let created = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&created);
        let stage = HickoryStage::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(HickoryDnsaddrResolver::default_resolver())
        });
        assert_eq!(created.load(std::sync::atomic::Ordering::SeqCst), 0);
        let first = stage.get().unwrap();
        let second = stage.get().unwrap();
        assert!(std::sync::Arc::ptr_eq(&first, &second));
        assert_eq!(created.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// go: "It should not include fallback if none was specified"
    /// (`TestDnsAddrResolveController`).
    #[test]
    fn fallback_stage_exists_only_when_configured() {
        assert!(HickoryDnsaddrResolver::new(None).fallback.is_none());
        assert!(HickoryDnsaddrResolver::new(Some("1.2.3.4".into()))
            .fallback
            .is_some());
    }
}
