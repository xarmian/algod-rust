//! Async DNS SRV resolution for peer discovery.
//!
//! Matches the behaviour of go-algorand's `tools/network/bootstrap.go`:
//! resolves `_<service>._<protocol>.<name>` SRV records, stripping trailing
//! dots from targets and skipping empty targets.
//!
//! The [`SrvResolver`] trait abstracts DNS lookups for testability.
//! [`HickorySrvResolver`] is the production implementation backed by
//! [`hickory_resolver::Resolver`] with DNSSEC enabled by default.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{ResolveError, TokioResolver};
use thiserror::Error;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced during DNS SRV resolution.
#[derive(Debug, Error)]
pub enum SrvResolveError {
    /// The `name` argument was empty.
    #[error("no DNS lookup due to empty name")]
    EmptyName,

    /// The `protocol` argument was not one of `tcp`, `udp`, or `tls`.
    #[error("unsupported protocol '{0}' specified")]
    UnsupportedProtocol(String),

    /// All resolver attempts (system, fallback, default) failed.
    #[error("DNS SRV lookup failed: system({system}), fallback({fallback}), default({default})")]
    AllResolversFailed {
        /// Error from the system resolver.
        system: String,
        /// Error from the fallback resolver (or "not configured").
        fallback: String,
        /// Error from the default resolver.
        default: String,
    },

    /// A single resolver attempt failed.
    #[error("DNS SRV lookup failed: {0}")]
    ResolveFailed(#[from] ResolveError),
}

// ---------------------------------------------------------------------------
// SrvRecord
// ---------------------------------------------------------------------------

/// A single DNS SRV record with the trailing dot stripped from the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    /// Target hostname (without trailing dot).
    pub target: String,
    /// Port number for the service.
    pub port: u16,
    /// Priority (lower is preferred).
    pub priority: u16,
    /// Weight (higher is preferred among equal-priority records).
    pub weight: u16,
}

// ---------------------------------------------------------------------------
// SrvResolver trait
// ---------------------------------------------------------------------------

/// Trait for DNS SRV resolution, enabling mock implementations in tests.
///
/// The method returns a boxed future because Rust 2021 does not support
/// `async fn` in traits without the `async-trait` crate.
pub trait SrvResolver: Send + Sync {
    /// Look up SRV records for `_<service>._<protocol>.<name>`.
    fn lookup_srv(
        &self,
        service: &str,
        protocol: &str,
        name: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SrvRecord>, SrvResolveError>> + Send + '_>>;
}

// ---------------------------------------------------------------------------
// HickorySrvResolver
// ---------------------------------------------------------------------------

/// Production [`SrvResolver`] backed by hickory-resolver with DNSSEC.
///
/// Mirrors go-algorand's `readFromSRV` resolver chain:
/// 1. Try the system resolver (OS-configured DNS servers).
/// 2. If that fails and a fallback address is configured, try the fallback.
/// 3. If that also fails (or no fallback was provided), try a default
///    resolver (Cloudflare + Google).
pub struct HickorySrvResolver {
    /// Optional fallback DNS server address (IP or hostname).
    fallback_dns: Option<String>,
}

impl HickorySrvResolver {
    /// Create a new resolver.
    ///
    /// `fallback_dns` is an optional IP address (e.g. `"8.8.8.8"`) used as a
    /// fallback when the system resolver fails, mirroring go-algorand's
    /// `fallbackDNSResolverAddress` parameter.
    pub fn new(fallback_dns: Option<String>) -> Self {
        Self { fallback_dns }
    }

    /// Build a hickory [`TokioResolver`] with the given config and DNSSEC
    /// validation enabled.
    fn build_resolver(config: ResolverConfig) -> TokioResolver {
        let provider = TokioConnectionProvider::default();
        let mut builder = TokioResolver::builder_with_config(config, provider);
        let opts = builder.options_mut();
        opts.validate = true; // Enable DNSSEC
        opts.try_tcp_on_error = true;
        builder.build()
    }

    /// Build a system resolver (uses OS DNS configuration).
    ///
    /// Uses `builder_tokio()` which reads `/etc/resolv.conf` on Unix or the
    /// registry on Windows to discover the system's DNS servers.
    fn system_resolver() -> Result<TokioResolver, ResolveError> {
        let mut builder = TokioResolver::builder_tokio().map_err(|e| {
            warn!("failed to read system DNS config: {e}");
            e
        })?;
        let opts = builder.options_mut();
        opts.validate = true; // Enable DNSSEC
        opts.try_tcp_on_error = true;
        Ok(builder.build())
    }

    /// Build a fallback resolver targeting a specific DNS server IP.
    fn fallback_resolver(addr: &str) -> Option<TokioResolver> {
        let ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                warn!("failed to parse fallback DNS address '{addr}': {e}");
                return None;
            }
        };
        let group = NameServerConfigGroup::from_ips_clear(&[ip], 53, true);
        let config = ResolverConfig::from_parts(None, vec![], group);
        Some(Self::build_resolver(config))
    }

    /// Build a default resolver using well-known public DNS servers
    /// (Cloudflare + Google), mirroring go-algorand's `DefaultResolver`.
    fn default_resolver() -> TokioResolver {
        // Combine Cloudflare and Google name servers for redundancy.
        let mut group = NameServerConfigGroup::cloudflare();
        group.merge(NameServerConfigGroup::google());
        let config = ResolverConfig::from_parts(None, vec![], group);
        Self::build_resolver(config)
    }

    /// Perform an SRV lookup using the given resolver, returning parsed
    /// [`SrvRecord`]s.
    async fn do_lookup(
        resolver: &TokioResolver,
        srv_name: &str,
    ) -> Result<Vec<SrvRecord>, ResolveError> {
        let lookup = resolver.srv_lookup(srv_name).await?;
        let records = lookup
            .iter()
            .filter_map(|srv| {
                let mut target = srv.target().to_string();
                if target.is_empty() || target == "." {
                    return None;
                }
                // Strip trailing dot (FQDN convention).
                if target.ends_with('.') {
                    target.pop();
                }
                if target.is_empty() {
                    return None;
                }
                Some(SrvRecord {
                    target,
                    port: srv.port(),
                    priority: srv.priority(),
                    weight: srv.weight(),
                })
            })
            .collect();
        Ok(records)
    }
}

impl SrvResolver for HickorySrvResolver {
    fn lookup_srv(
        &self,
        service: &str,
        protocol: &str,
        name: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SrvRecord>, SrvResolveError>> + Send + '_>> {
        let service = service.to_string();
        let protocol = protocol.to_string();
        let name = name.to_string();

        Box::pin(async move {
            // 1. Validate inputs.
            if name.is_empty() {
                debug!("no DNS lookup due to empty name");
                return Err(SrvResolveError::EmptyName);
            }
            if protocol != "tcp" && protocol != "udp" && protocol != "tls" {
                return Err(SrvResolveError::UnsupportedProtocol(protocol));
            }

            // 2. Construct the SRV query name: _<service>._<protocol>.<name>
            let srv_name = format!("_{service}._{protocol}.{name}");

            // 3. Try system resolver first.
            let sys_err: String = match Self::system_resolver() {
                Ok(resolver) => match Self::do_lookup(&resolver, &srv_name).await {
                    Ok(records) => return Ok(records),
                    Err(e) => {
                        info!("DNS SRV lookup failed with system resolver: {e}");
                        e.to_string()
                    }
                },
                Err(e) => {
                    info!("failed to create system resolver: {e}");
                    e.to_string()
                }
            };

            // 4. If system fails and fallback is configured, try fallback.
            let fb_err: String = if let Some(ref fallback_addr) = self.fallback_dns {
                match Self::fallback_resolver(fallback_addr) {
                    Some(resolver) => match Self::do_lookup(&resolver, &srv_name).await {
                        Ok(records) => return Ok(records),
                        Err(e) => {
                            info!(
                                "DNS SRV lookup failed with fallback '{fallback_addr}' resolver: {e}"
                            );
                            e.to_string()
                        }
                    },
                    None => "fallback address could not be parsed".to_string(),
                }
            } else {
                "not configured".to_string()
            };

            // 5. Try default resolver (well-known public DNS).
            let default_resolver = Self::default_resolver();
            match Self::do_lookup(&default_resolver, &srv_name).await {
                Ok(records) => Ok(records),
                Err(e) => {
                    let default_err: String = e.to_string();
                    info!("DNS SRV lookup failed with default resolver: {default_err}");
                    Err(SrvResolveError::AllResolversFailed {
                        system: sys_err,
                        fallback: fb_err,
                        default: default_err,
                    })
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Helper function
// ---------------------------------------------------------------------------

/// Resolve SRV records and return `"host:port"` address strings.
///
/// This is the Rust equivalent of go-algorand's `ReadFromSRV` function:
/// it queries for SRV records, strips trailing dots from targets, skips
/// empty targets, and formats each record as `"host:port"`.
pub async fn resolve_addresses(
    resolver: &dyn SrvResolver,
    service: &str,
    protocol: &str,
    name: &str,
) -> Result<Vec<String>, SrvResolveError> {
    let records = resolver.lookup_srv(service, protocol, name).await?;
    let addrs = records
        .into_iter()
        .map(|r| format!("{}:{}", r.target, r.port))
        .collect();
    Ok(addrs)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Mock resolver for unit tests
    // -----------------------------------------------------------------------

    /// A mock [`SrvResolver`] that returns a pre-configured list of records.
    struct MockSrvResolver {
        records: Result<Vec<SrvRecord>, SrvResolveError>,
    }

    impl MockSrvResolver {
        fn with_records(records: Vec<SrvRecord>) -> Self {
            Self {
                records: Ok(records),
            }
        }

        fn with_error(err: SrvResolveError) -> Self {
            Self { records: Err(err) }
        }
    }

    impl SrvResolver for MockSrvResolver {
        fn lookup_srv(
            &self,
            _service: &str,
            _protocol: &str,
            _name: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<SrvRecord>, SrvResolveError>> + Send + '_>>
        {
            Box::pin(async {
                match &self.records {
                    Ok(records) => Ok(records.clone()),
                    Err(_) => Err(SrvResolveError::EmptyName), // simplified for mock
                }
            })
        }
    }

    // -----------------------------------------------------------------------
    // A validating mock that checks service/protocol/name
    // -----------------------------------------------------------------------

    struct ValidatingMockResolver {
        expected_service: String,
        expected_protocol: String,
        expected_name: String,
        records: Vec<SrvRecord>,
    }

    impl SrvResolver for ValidatingMockResolver {
        fn lookup_srv(
            &self,
            service: &str,
            protocol: &str,
            name: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<SrvRecord>, SrvResolveError>> + Send + '_>>
        {
            assert_eq!(service, self.expected_service);
            assert_eq!(protocol, self.expected_protocol);
            assert_eq!(name, self.expected_name);
            let records = self.records.clone();
            Box::pin(async move { Ok(records) })
        }
    }

    // -----------------------------------------------------------------------
    // SrvRecord tests
    // -----------------------------------------------------------------------

    #[test]
    fn srv_record_equality() {
        let a = SrvRecord {
            target: "relay1.algorand.network".to_string(),
            port: 4160,
            priority: 1,
            weight: 1,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn srv_record_debug() {
        let r = SrvRecord {
            target: "r1.example.com".to_string(),
            port: 443,
            priority: 10,
            weight: 20,
        };
        let debug = format!("{r:?}");
        assert!(debug.contains("r1.example.com"));
        assert!(debug.contains("443"));
    }

    // -----------------------------------------------------------------------
    // resolve_addresses tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn resolve_addresses_formats_host_port() {
        let resolver = MockSrvResolver::with_records(vec![
            SrvRecord {
                target: "relay1.algorand.network".to_string(),
                port: 4160,
                priority: 1,
                weight: 1,
            },
            SrvRecord {
                target: "relay2.algorand.network".to_string(),
                port: 4161,
                priority: 2,
                weight: 1,
            },
        ]);

        let addrs = resolve_addresses(
            &resolver,
            "algobootstrap",
            "tcp",
            "mainnet.algorand.network",
        )
        .await
        .unwrap();

        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], "relay1.algorand.network:4160");
        assert_eq!(addrs[1], "relay2.algorand.network:4161");
    }

    #[tokio::test]
    async fn resolve_addresses_empty_records() {
        let resolver = MockSrvResolver::with_records(vec![]);
        let addrs = resolve_addresses(&resolver, "algobootstrap", "tcp", "example.com")
            .await
            .unwrap();
        assert!(addrs.is_empty());
    }

    #[tokio::test]
    async fn resolve_addresses_error_propagated() {
        let resolver = MockSrvResolver::with_error(SrvResolveError::EmptyName);
        let result = resolve_addresses(&resolver, "svc", "tcp", "example.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn resolve_addresses_passes_correct_args() {
        let resolver = ValidatingMockResolver {
            expected_service: "algobootstrap".to_string(),
            expected_protocol: "tcp".to_string(),
            expected_name: "mainnet.algorand.network".to_string(),
            records: vec![SrvRecord {
                target: "r1.example.com".to_string(),
                port: 4160,
                priority: 1,
                weight: 1,
            }],
        };

        let addrs = resolve_addresses(
            &resolver,
            "algobootstrap",
            "tcp",
            "mainnet.algorand.network",
        )
        .await
        .unwrap();

        assert_eq!(addrs, vec!["r1.example.com:4160"]);
    }

    // -----------------------------------------------------------------------
    // Input validation tests (via HickorySrvResolver)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn empty_name_returns_error() {
        let resolver = HickorySrvResolver::new(None);
        let result = resolver.lookup_srv("svc", "tcp", "").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SrvResolveError::EmptyName),
            "expected EmptyName, got: {err}"
        );
    }

    #[tokio::test]
    async fn unsupported_protocol_returns_error() {
        let resolver = HickorySrvResolver::new(None);

        for proto in &["http", "https", "quic", ""] {
            let result = resolver.lookup_srv("svc", proto, "example.com").await;
            assert!(result.is_err(), "expected error for protocol '{proto}'");
            let err = result.unwrap_err();
            assert!(
                matches!(err, SrvResolveError::UnsupportedProtocol(_)),
                "expected UnsupportedProtocol for '{proto}', got: {err}"
            );
        }
    }

    #[tokio::test]
    async fn valid_protocols_accepted() {
        // These should pass validation (may fail at DNS level, but not
        // at the protocol-check level).
        let resolver = HickorySrvResolver::new(None);
        for proto in &["tcp", "udp", "tls"] {
            let result = resolver
                .lookup_srv("svc", proto, "nonexistent.invalid.")
                .await;
            // Should fail with a DNS error, not UnsupportedProtocol.
            if let Err(e) = result {
                assert!(
                    !matches!(e, SrvResolveError::UnsupportedProtocol(_)),
                    "protocol '{proto}' should be accepted, got: {e}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Error display tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_empty_name() {
        let err = SrvResolveError::EmptyName;
        assert_eq!(err.to_string(), "no DNS lookup due to empty name");
    }

    #[test]
    fn error_display_unsupported_protocol() {
        let err = SrvResolveError::UnsupportedProtocol("http".to_string());
        assert_eq!(err.to_string(), "unsupported protocol 'http' specified");
    }

    #[test]
    fn error_display_all_resolvers_failed() {
        let err = SrvResolveError::AllResolversFailed {
            system: "timeout".to_string(),
            fallback: "not configured".to_string(),
            default: "NXDOMAIN".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("timeout"));
        assert!(msg.contains("not configured"));
        assert!(msg.contains("NXDOMAIN"));
    }

    // -----------------------------------------------------------------------
    // HickorySrvResolver construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolver_without_fallback() {
        let resolver = HickorySrvResolver::new(None);
        assert!(resolver.fallback_dns.is_none());
    }

    #[test]
    fn resolver_with_fallback() {
        let resolver = HickorySrvResolver::new(Some("8.8.8.8".to_string()));
        assert_eq!(resolver.fallback_dns.as_deref(), Some("8.8.8.8"));
    }

    // -----------------------------------------------------------------------
    // Trailing-dot and empty-target filtering tests
    // -----------------------------------------------------------------------

    /// Verifies that resolve_addresses correctly formats targets that
    /// have already been cleaned (no trailing dot, non-empty).
    #[tokio::test]
    async fn trailing_dot_stripped_in_output() {
        // The HickorySrvResolver strips trailing dots internally.
        // Here we verify that resolve_addresses faithfully formats
        // whatever the resolver returns.
        let resolver = MockSrvResolver::with_records(vec![SrvRecord {
            target: "relay.algorand.network".to_string(),
            port: 4160,
            priority: 1,
            weight: 1,
        }]);

        let addrs = resolve_addresses(&resolver, "algobootstrap", "tcp", "test.algorand.network")
            .await
            .unwrap();

        assert_eq!(addrs, vec!["relay.algorand.network:4160"]);
    }

    /// Verify that single-record results work correctly.
    #[tokio::test]
    async fn single_record_resolve() {
        let resolver = MockSrvResolver::with_records(vec![SrvRecord {
            target: "node.example.com".to_string(),
            port: 8080,
            priority: 0,
            weight: 0,
        }]);

        let addrs = resolve_addresses(&resolver, "svc", "tcp", "example.com")
            .await
            .unwrap();

        assert_eq!(addrs, vec!["node.example.com:8080"]);
    }

    /// Verify that records with priority and weight are preserved.
    #[tokio::test]
    async fn priority_and_weight_preserved() {
        let resolver = MockSrvResolver::with_records(vec![
            SrvRecord {
                target: "a.example.com".to_string(),
                port: 443,
                priority: 10,
                weight: 60,
            },
            SrvRecord {
                target: "b.example.com".to_string(),
                port: 443,
                priority: 10,
                weight: 40,
            },
            SrvRecord {
                target: "c.example.com".to_string(),
                port: 443,
                priority: 20,
                weight: 100,
            },
        ]);

        let result = resolver
            .lookup_srv("svc", "tcp", "example.com")
            .await
            .unwrap();

        assert_eq!(result[0].priority, 10);
        assert_eq!(result[0].weight, 60);
        assert_eq!(result[1].priority, 10);
        assert_eq!(result[1].weight, 40);
        assert_eq!(result[2].priority, 20);
        assert_eq!(result[2].weight, 100);
    }

    /// Verify the archival service SRV query pattern.
    #[tokio::test]
    async fn archival_srv_query() {
        let resolver = ValidatingMockResolver {
            expected_service: "archive".to_string(),
            expected_protocol: "tcp".to_string(),
            expected_name: "mainnet.algorand.network".to_string(),
            records: vec![SrvRecord {
                target: "archival1.algorand.network".to_string(),
                port: 4160,
                priority: 1,
                weight: 1,
            }],
        };

        let addrs = resolve_addresses(&resolver, "archive", "tcp", "mainnet.algorand.network")
            .await
            .unwrap();

        assert_eq!(addrs, vec!["archival1.algorand.network:4160"]);
    }
}
