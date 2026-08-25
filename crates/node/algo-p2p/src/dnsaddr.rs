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

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{ResolveError, TokioResolver};
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
    fallback_dns: Option<String>,
}

impl HickoryDnsaddrResolver {
    /// Create a new resolver. `fallback_dns` is an optional IP address used
    /// as a fallback when the system resolver fails.
    pub fn new(fallback_dns: Option<String>) -> Self {
        Self { fallback_dns }
    }

    fn build_resolver(config: ResolverConfig) -> TokioResolver {
        let provider = TokioConnectionProvider::default();
        let mut builder = TokioResolver::builder_with_config(config, provider);
        let opts = builder.options_mut();
        opts.validate = true;
        opts.try_tcp_on_error = true;
        builder.build()
    }

    fn system_resolver() -> Result<TokioResolver, ResolveError> {
        let mut builder = TokioResolver::builder_tokio()?;
        let opts = builder.options_mut();
        opts.validate = true;
        opts.try_tcp_on_error = true;
        Ok(builder.build())
    }

    fn fallback_resolver(addr: &str) -> Option<TokioResolver> {
        let ip: IpAddr = addr.parse().ok()?;
        let group = NameServerConfigGroup::from_ips_clear(&[ip], 53, true);
        let config = ResolverConfig::from_parts(None, vec![], group);
        Some(Self::build_resolver(config))
    }

    fn default_resolver() -> TokioResolver {
        let mut group = NameServerConfigGroup::cloudflare();
        group.merge(NameServerConfigGroup::google());
        let config = ResolverConfig::from_parts(None, vec![], group);
        Self::build_resolver(config)
    }

    async fn do_lookup(resolver: &TokioResolver, name: &str) -> Result<Vec<String>, ResolveError> {
        let lookup = resolver.txt_lookup(name).await?;
        let values = lookup
            .iter()
            .filter_map(|txt| {
                let bytes: Vec<u8> = txt
                    .txt_data()
                    .iter()
                    .flat_map(|c| c.iter().copied())
                    .collect();
                String::from_utf8(bytes).ok()
            })
            .collect();
        Ok(values)
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

            let sys_err = match Self::system_resolver() {
                Ok(resolver) => match Self::do_lookup(&resolver, &name).await {
                    Ok(values) => return Ok(values),
                    Err(e) => e.to_string(),
                },
                Err(e) => e.to_string(),
            };

            let fb_err = if let Some(ref fallback_addr) = self.fallback_dns {
                match Self::fallback_resolver(fallback_addr) {
                    Some(resolver) => match Self::do_lookup(&resolver, &name).await {
                        Ok(values) => return Ok(values),
                        Err(e) => e.to_string(),
                    },
                    None => "fallback address could not be parsed".to_string(),
                }
            } else {
                "not configured".to_string()
            };

            match Self::do_lookup(&Self::default_resolver(), &name).await {
                Ok(values) => Ok(values),
                Err(e) => {
                    let default_err = e.to_string();
                    warn!(
                        domain,
                        sys_err, fb_err, default_err, "dnsaddr TXT lookup failed"
                    );
                    Err(DnsaddrError::AllResolversFailed {
                        domain,
                        system: sys_err,
                        fallback: fb_err,
                        default: default_err,
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

#[cfg(test)]
mod tests {
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
}
