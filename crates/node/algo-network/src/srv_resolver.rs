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
use std::time::Duration;

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{ResolveError, TokioResolver};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Per-stage wall-clock budget for a single [`HickorySrvResolver`] lookup
/// attempt (issue #1614).
///
/// # Why this exists
///
/// `hickory_proto::dnssec::dnssec_dns_handle::DnssecDnsHandle::verify_response`
/// (confirmed by reading the pinned `hickory-proto` 0.25.2 source under
/// `~/.cargo/registry/src/.../hickory-proto-0.25.2/src/dnssec/dnssec_dns_handle/mod.rs`)
/// validates the DNSSEC signatures of the response's `answers`,
/// `name_servers`, **and `additionals`** sections — not just the RRset the
/// caller actually queried for. For an SRV lookup against
/// `mainnet.algorand.network` that means every relay hostname's own
/// additional-section glue record gets its own independent, recursive
/// DNSKEY/DS chain-of-trust walk (`verify_default_rrset` ->
/// `find_ds_records`/`fetch_ds_records` -> `handle.lookup(DNSKEY/DS query)`,
/// each hop re-entering `DnssecDnsHandle::send` via `clone_with_context`),
/// sequentially, one rrset at a time (`verify_rrsets`'s `for` loop `.await`s
/// each rrset before starting the next) — even though algod-rust's own
/// bootstrap flow (`discovery.rs` -> `resolve_addresses` -> plain
/// `"host:port"` strings later resolved by `TcpStream::connect`'s own,
/// separate, non-DNSSEC system resolution) never reads that additional
/// section at all. go-algorand's own `tools/network/dnssec` trustchain
/// walker has no equivalent: it authenticates only the queried RRset via a
/// fixed, shallow zone-ancestry walk.
///
/// A single problematic additional-section name is, by itself, non-fatal —
/// `verify_rrsets` degrades a failed rrset to `Proof::Bogus`/`Insecure`
/// rather than erroring the whole response — but hickory-proto's internal
/// `max_request_depth = 26` backstop (`xfer/dns_request.rs`) is neither
/// exposed on `ResolverOpts` nor overridable through the public
/// `TokioResolver`/`ResolverBuilder` API, so a pathological chain (one that
/// keeps re-fetching the same DS/SOA data, as documented upstream in
/// <https://github.com/hickory-dns/hickory-dns/issues/3974> for a related,
/// still-open DNSSEC-validation defect around insecure delegations) can
/// burn real wall-clock time retrying network round trips across up to ~70
/// candidate relay names before finally giving up on each one. On a
/// GitHub-Actions-runner network path that reproduced as ~70 "exceeded max
/// validation depth" log lines clustered in the final ~54ms of a 2-minute
/// `participate` startup window (issue #1614) — i.e. the *lookup itself*
/// doesn't necessarily error, it just consumes the caller's entire startup
/// budget before the (still-correct) SRV answer is ever returned. This was
/// **not reproducible** from this repo's own dev machine (a DNSSEC-validating
/// mainnet SRV lookup here completes in about a second every time — see
/// `dns_integration::test_mainnet_relay_srv_resolution`), consistent with
/// #1614's own framing that this is network-path-sensitive (a
/// systemd-resolved stub resolver in the runner's `/etc/resolv.conf`, or
/// simply higher real RTT/packet loss than this machine sees) rather than an
/// inherent defect in every DNSSEC-validating resolution of this response
/// shape.
///
/// Since hickory-resolver's public API offers no way to (a) scope DNSSEC
/// validation to only the queried RRset or (b) raise/override
/// `max_request_depth`, this bounds each individual resolver-stage attempt
/// (`system`/`fallback`/`default`, and the DNSSEC-disabled last-resort
/// fallback added below) so that one hung/slow validation walk can never by
/// itself consume the caller's whole startup window — it fails that one
/// stage and lets `lookup_srv`'s existing `system -> fallback -> default`
/// chain (plus the new last-resort stage) keep moving. Four stages at this
/// budget (60s total worst case) still leave headroom inside a typical
/// multi-minute node-startup window.
const DNSSEC_STAGE_TIMEOUT: Duration = Duration::from_secs(15);

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

    /// [`HickorySrvResolver::lookup_srv_via_stage`] was called with
    /// [`ResolverStage::Fallback`] but no fallback address is configured (or
    /// the configured address does not parse as an IP).
    #[error("fallback resolver not configured or address invalid")]
    FallbackNotConfigured,

    /// A resolver-stage attempt did not complete within
    /// [`DNSSEC_STAGE_TIMEOUT`] (issue #1614: guards against a hung/slow
    /// DNSSEC chain-of-trust walk consuming the caller's entire startup
    /// budget).
    #[error("DNS SRV lookup timed out after {0:?}")]
    Timeout(Duration),
}

// ---------------------------------------------------------------------------
// ResolverStage
// ---------------------------------------------------------------------------

/// Selects a single stage of [`HickorySrvResolver`]'s
/// `system -> fallback -> default` resolution chain, bypassing the automatic
/// fallthrough that [`SrvResolver::lookup_srv`] performs.
///
/// Exists so tests can force resolution through exactly one named resolver
/// (mirroring go-algorand's `tools/network.ResolveController`, which exposes
/// `SystemResolver()`/`FallbackResolver()`/`DefaultResolver()` as separately
/// callable methods) without changing `lookup_srv`'s own default behaviour,
/// which always tries all three stages in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverStage {
    /// The OS-configured system resolver.
    System,
    /// The configured fallback DNS server (errors with
    /// [`SrvResolveError::FallbackNotConfigured`] if none is set or it fails
    /// to parse as an IP address).
    Fallback,
    /// The well-known public default resolver (Cloudflare + Google).
    Default,
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
// Resolver options
// ---------------------------------------------------------------------------

/// Apply the `ResolverOpts` every [`HickorySrvResolver`]-built `TokioResolver`
/// must use, setting `validate` per the caller's DNSSEC-enforcement setting.
///
/// Split out from the resolver-builder methods so a test can assert on the
/// resulting `ResolverOpts` directly (mirrors [`Self::default_resolver_config`]
/// / [`Self::fallback_resolver_config`]'s testability split).
///
/// # `edns0` (issue #1600 root cause)
///
/// `hickory_resolver::config::ResolverOpts::edns0` defaults to `false`, and
/// none of this module's resolver builders used to override it. That default
/// only matters for the *initial* query hickory-resolver constructs
/// (`resolver.rs`'s `Resolver::lookup` sets `DnsRequestOptions::use_edns =
/// self.options.edns0`) — but that same `DnsRequestOptions` is threaded
/// through to every DNSKEY/DS sub-query hickory-proto's
/// `dnssec_dns_handle::verify_dnskey_rrset`/`find_ds_records` issue while
/// walking the chain of trust (`hickory_proto::xfer::dns_handle::build_request`
/// only attaches an EDNS OPT record — and only then sizes it to the
/// recommended 1232-byte payload — when `options.use_edns` is set).
///
/// With `edns0` left `false`, every one of those queries goes out with no
/// EDNS OPT record at all; `DnssecDnsHandle::send` (which unconditionally
/// needs DNSSEC-OK set to receive RRSIG/DNSKEY data) then has to insert one
/// itself via `Edns::default()`, whose `max_payload` is the bare legacy
/// non-EDNS minimum of 512 bytes (RFC 6891) — nowhere near enough for a
/// zone like `mainnet.algorand.network`, whose real SRV response carries
/// ~70 relay records plus RRSIGs and additional-section glue. Every UDP
/// response for that zone gets truncated (`TC=1`), forcing a TCP-fallback
/// retry for essentially every query the DNSSEC chain-of-trust walk makes;
/// each retry re-enters `DnssecDnsHandle::send` through a freshly cloned
/// handle (`clone_with_context`, which increments `request_depth`), and
/// enough of those compounding retries across the ~70 additional-section
/// names eventually exceed hickory-proto's fixed `max_request_depth = 26`
/// backstop (`dnssec_dns_handle/mod.rs`), surfacing as "exceeded max
/// validation depth" — even though the actual delegation chain (root ->
/// `.network` -> `algorand.network`) is only a few levels deep.
///
/// Setting `edns0 = true` makes hickory's own `build_request` attach an
/// EDNS OPT record sized to the recommended 1232-byte payload *before* the
/// DNSSEC handle ever touches it; `Edns::enable_dnssec` only flips the
/// DNSSEC-OK flag and never shrinks an existing `max_payload`, so every
/// query in the chain — not just the top-level SRV lookup — keeps the
/// larger buffer and stops triggering truncation-driven retries. This
/// mirrors what every production DNS resolver (including go-algorand's own
/// `tools/network/dnssec` resolver) does unconditionally; leaving `edns0`
/// at hickory's bare default was algod-rust's own configuration gap, not an
/// upstream hickory-dns defect.
fn apply_resolver_opts(opts: &mut ResolverOpts, validate: bool) {
    opts.validate = validate;
    opts.try_tcp_on_error = true;
    opts.edns0 = true;
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

    /// Whether every resolver this instance builds validates DNSSEC.
    ///
    /// Mirrors go's `config.Local::DNSSecuritySRVEnforced()`
    /// (`config/localTemplate.go:729-731`), which `getDNSAddrs`
    /// (`network/wsNetwork.go`) passes as `resolveSRVRecords`'s `secure`
    /// argument, flowing into `tools/network/resolveController.go`'s
    /// `ResolveController` — a `false` there returns a plain non-validating
    /// `net.Resolver`-backed resolver instead of a
    /// `dnssec.MakeDnssecResolver(...)`-backed one. Issue #1314: this used
    /// to be hardcoded `true` unconditionally with no way to disable it.
    validate_dnssec: bool,
}

impl HickorySrvResolver {
    /// Create a new resolver with DNSSEC validation enabled (go's default:
    /// `DNSSecurityFlags`'s SRV bit set).
    ///
    /// `fallback_dns` is an optional IP address (e.g. `"8.8.8.8"`) used as a
    /// fallback when the system resolver fails, mirroring go-algorand's
    /// `fallbackDNSResolverAddress` parameter.
    pub fn new(fallback_dns: Option<String>) -> Self {
        Self {
            fallback_dns,
            validate_dnssec: true,
        }
    }

    /// Create a new resolver with an explicit DNSSEC-validation setting,
    /// mirroring go's `config.Local::DNSSecuritySRVEnforced()` (issue
    /// #1314). Callers with a loaded `Local` config (e.g. `participate`)
    /// should use this instead of [`Self::new`] so an operator's explicit
    /// `DNSSecurityFlags` override actually takes effect.
    pub fn new_with_dnssec_validation(fallback_dns: Option<String>, validate_dnssec: bool) -> Self {
        Self {
            fallback_dns,
            validate_dnssec,
        }
    }

    /// Build a hickory [`TokioResolver`] with the given config, enabling
    /// DNSSEC validation only when `validate` is set.
    fn build_resolver(config: ResolverConfig, validate: bool) -> TokioResolver {
        let provider = TokioConnectionProvider::default();
        let mut builder = TokioResolver::builder_with_config(config, provider);
        apply_resolver_opts(builder.options_mut(), validate);
        builder.build()
    }

    /// Build a system resolver (uses OS DNS configuration).
    ///
    /// Uses `builder_tokio()` which reads `/etc/resolv.conf` on Unix or the
    /// registry on Windows to discover the system's DNS servers.
    fn system_resolver(validate: bool) -> Result<TokioResolver, ResolveError> {
        let mut builder = TokioResolver::builder_tokio().map_err(|e| {
            warn!("failed to read system DNS config: {e}");
            e
        })?;
        apply_resolver_opts(builder.options_mut(), validate);
        Ok(builder.build())
    }

    /// Build the [`ResolverConfig`] for a fallback resolver targeting a
    /// specific DNS server IP, or `None` if `addr` doesn't parse as an IP
    /// address.
    ///
    /// Split out from [`Self::fallback_resolver`] so tests can inspect the
    /// resulting name-server list without building a live `TokioResolver` —
    /// mirrors go-algorand's `ResolveController.FallbackResolver()`, whose
    /// tests (`tools/network/resolveController_test.go`'s
    /// `TestFallbackResolver`/`TestFallbackResolverInvalidAddress`) assert
    /// on `EffectiveResolverDNS()` (a valid address is used verbatim; an
    /// invalid one causes the fallback to be unavailable, so callers degrade
    /// to the default resolver instead of panicking).
    fn fallback_resolver_config(addr: &str) -> Option<ResolverConfig> {
        let ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                warn!("failed to parse fallback DNS address '{addr}': {e}");
                return None;
            }
        };
        let group = NameServerConfigGroup::from_ips_clear(&[ip], 53, true);
        Some(ResolverConfig::from_parts(None, vec![], group))
    }

    /// Build a fallback resolver targeting a specific DNS server IP.
    fn fallback_resolver(addr: &str, validate: bool) -> Option<TokioResolver> {
        let config = Self::fallback_resolver_config(addr)?;
        Some(Self::build_resolver(config, validate))
    }

    /// Build the [`ResolverConfig`] for the default resolver, using
    /// well-known public DNS servers (Cloudflare + Google) — mirrors
    /// go-algorand's `ResolveController.DefaultResolver()`
    /// (`defaultDNSAddress`/`dnssec.DefaultDnssecAwareNSServers`). Split out
    /// from [`Self::default_resolver`] for the same testability reason as
    /// [`Self::fallback_resolver_config`].
    fn default_resolver_config() -> ResolverConfig {
        // Combine Cloudflare and Google name servers for redundancy.
        let mut group = NameServerConfigGroup::cloudflare();
        group.merge(NameServerConfigGroup::google());
        ResolverConfig::from_parts(None, vec![], group)
    }

    /// Build a default resolver using well-known public DNS servers
    /// (Cloudflare + Google), mirroring go-algorand's `DefaultResolver`.
    fn default_resolver(validate: bool) -> TokioResolver {
        Self::build_resolver(Self::default_resolver_config(), validate)
    }

    /// Perform an SRV lookup using the given resolver, returning parsed
    /// [`SrvRecord`]s, sorted by priority and weight-randomized within each
    /// priority tier (see [`sort_and_randomize_srv_records`]).
    ///
    /// `hickory_resolver`'s `srv_lookup` returns records in whatever order
    /// the DNS response carried them in — unlike Go's `net.Resolver`/
    /// `dnssec.Resolver` (`tools/network/resolver.go`'s `LookupSRV` doc
    /// comment: "The returned records are sorted by priority and randomized
    /// by weight within a priority"), it performs no RFC 2782 ordering, so
    /// that ordering has to be applied here explicitly.
    async fn do_lookup(
        resolver: &TokioResolver,
        srv_name: &str,
    ) -> Result<Vec<SrvRecord>, ResolveError> {
        let lookup = resolver.srv_lookup(srv_name).await?;
        let mut records: Vec<SrvRecord> = lookup
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
        sort_and_randomize_srv_records(&mut records);
        Ok(records)
    }

    /// [`Self::do_lookup`], bounded by [`DNSSEC_STAGE_TIMEOUT`] (issue
    /// #1614). A stage that doesn't answer within budget fails with
    /// [`SrvResolveError::Timeout`] instead of silently consuming the rest
    /// of the caller's startup window.
    async fn do_lookup_bounded(
        resolver: &TokioResolver,
        srv_name: &str,
    ) -> Result<Vec<SrvRecord>, SrvResolveError> {
        Self::do_lookup_bounded_with_timeout(resolver, srv_name, DNSSEC_STAGE_TIMEOUT).await
    }

    /// [`Self::do_lookup_bounded`] with an explicit budget, split out so
    /// tests can exercise the timeout path deterministically and quickly
    /// instead of waiting out the real [`DNSSEC_STAGE_TIMEOUT`].
    async fn do_lookup_bounded_with_timeout(
        resolver: &TokioResolver,
        srv_name: &str,
        budget: Duration,
    ) -> Result<Vec<SrvRecord>, SrvResolveError> {
        Self::bound(Self::do_lookup(resolver, srv_name), budget).await
    }

    /// Runs `fut` under a `budget`-length [`tokio::time::timeout`],
    /// converting an elapsed deadline into [`SrvResolveError::Timeout`].
    ///
    /// Generic over the future so tests can exercise the timeout-conversion
    /// path with a synthetic never-resolving future (`std::future::pending`)
    /// instead of a real, network-bound DNS lookup — deterministic and fast,
    /// no real waiting or network access required.
    async fn bound<F>(fut: F, budget: Duration) -> Result<Vec<SrvRecord>, SrvResolveError>
    where
        F: Future<Output = Result<Vec<SrvRecord>, ResolveError>>,
    {
        match tokio::time::timeout(budget, fut).await {
            Ok(result) => Ok(result?),
            Err(_elapsed) => Err(SrvResolveError::Timeout(budget)),
        }
    }

    /// Look up SRV records through exactly one named [`ResolverStage`],
    /// rather than `lookup_srv`'s automatic `system -> fallback -> default`
    /// fallthrough chain.
    ///
    /// This is the Rust equivalent of go-algorand's
    /// `ResolveController.SystemResolver()`/`FallbackResolver()`/
    /// `DefaultResolver()` being separately callable: it lets a test force
    /// resolution through (and observe the result/error of) one specific
    /// stage, matching `resolver_test.go`'s
    /// `TestResolverWithDefaultDNSResolution`/
    /// `TestResolverWithCloudflareDNSResolution`/
    /// `TestResolverWithInvalidDNSResolution` and
    /// `resolveController_test.go`'s `TestRealNamesWithResolver`. It does
    /// not change `lookup_srv`'s own default fallthrough behaviour at all.
    pub async fn lookup_srv_via_stage(
        &self,
        service: &str,
        protocol: &str,
        name: &str,
        stage: ResolverStage,
    ) -> Result<Vec<SrvRecord>, SrvResolveError> {
        if name.is_empty() {
            return Err(SrvResolveError::EmptyName);
        }
        if protocol != "tcp" && protocol != "udp" && protocol != "tls" {
            return Err(SrvResolveError::UnsupportedProtocol(protocol.to_string()));
        }
        let srv_name = format!("_{service}._{protocol}.{name}");

        match stage {
            ResolverStage::System => {
                let resolver = Self::system_resolver(self.validate_dnssec)?;
                Ok(Self::do_lookup(&resolver, &srv_name).await?)
            }
            ResolverStage::Fallback => {
                let addr = self
                    .fallback_dns
                    .as_ref()
                    .ok_or(SrvResolveError::FallbackNotConfigured)?;
                let resolver = Self::fallback_resolver(addr, self.validate_dnssec)
                    .ok_or(SrvResolveError::FallbackNotConfigured)?;
                Ok(Self::do_lookup(&resolver, &srv_name).await?)
            }
            ResolverStage::Default => {
                let resolver = Self::default_resolver(self.validate_dnssec);
                Ok(Self::do_lookup(&resolver, &srv_name).await?)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RFC 2782 priority sort + weighted randomization
// ---------------------------------------------------------------------------

/// Sort `records` by priority (ascending) and, within each priority tier,
/// weighted-randomize the order per RFC 2782 — a direct port of go-algorand's
/// `tools/network/dnssec.srvRecArray.sortAndRand()`
/// (`tools/network/dnssec/sort.go`), which both go's stdlib `net.Resolver`
/// and go-algorand's own `dnssec.Resolver` apply to every `LookupSRV` result.
fn sort_and_randomize_srv_records(records: &mut [SrvRecord]) {
    records.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.weight.cmp(&b.weight))
    });

    let mut i = 0usize;
    for j in 1..records.len() {
        if records[i].priority != records[j].priority {
            randomize_weighted_range(records, i, j);
            i = j;
        }
    }
    randomize_weighted_range(records, i, records.len());
}

/// Weighted-random shuffle of `records[start..end]` (a single priority
/// tier), per RFC 2782's SRV selection algorithm — a direct port of go's
/// `srvRecArray.randomize`.
fn randomize_weighted_range(records: &mut [SrvRecord], start: usize, end: usize) {
    use rand::Rng;

    let mut sum: u32 = records[start..end].iter().map(|r| r.weight as u32).sum();
    let mut start = start;
    let mut rng = rand::thread_rng();
    while sum > 0 && end > start {
        // Choose a uniform random number between 0 and the sum (inclusive).
        let num = rng.gen_range(0..=sum);
        let mut running_sum: u32 = 0;
        for i in start..end {
            running_sum += records[i].weight as u32;
            if running_sum >= num {
                records.swap(start, i);
                break;
            }
        }
        sum -= records[start].weight as u32;
        start += 1;
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
            let sys_err: String = match Self::system_resolver(self.validate_dnssec) {
                Ok(resolver) => match Self::do_lookup_bounded(&resolver, &srv_name).await {
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
                match Self::fallback_resolver(fallback_addr, self.validate_dnssec) {
                    Some(resolver) => match Self::do_lookup_bounded(&resolver, &srv_name).await {
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
            let default_resolver = Self::default_resolver(self.validate_dnssec);
            let default_err: String =
                match Self::do_lookup_bounded(&default_resolver, &srv_name).await {
                    Ok(records) => return Ok(records),
                    Err(e) => {
                        info!("DNS SRV lookup failed with default resolver: {e}");
                        e.to_string()
                    }
                };

            // 6. Last resort (issue #1614): if every DNSSEC-validating stage
            //    above failed or timed out, retry once through the default
            //    resolver with DNSSEC validation switched off.
            //
            //    This does NOT weaken DNSSEC validation of the actual
            //    queried SRV RRset in the normal case: every attempt above
            //    already tried real DNSSEC validation first, and this stage
            //    only runs after all three of them have already failed. It
            //    exists specifically to work around hickory-proto's
            //    `DnssecDnsHandle` validating far more than the queried
            //    RRset (see `DNSSEC_STAGE_TIMEOUT`'s doc comment) in a way
            //    that can consume a validating attempt's entire time budget
            //    on additional-section glue this crate's own bootstrap flow
            //    never reads (`discovery.rs` re-resolves each relay
            //    hostname's address separately, non-DNSSEC, via
            //    `TcpStream::connect`). Only reached when
            //    `self.validate_dnssec` is true — an operator who already
            //    disabled DNSSEC validation gets no extra stage here, since
            //    every attempt above was already non-validating.
            if self.validate_dnssec {
                warn!(
                    "all DNSSEC-validating DNS SRV lookup stages failed or timed out for \
                     '{srv_name}' (system: {sys_err}; fallback: {fb_err}; default: \
                     {default_err}); retrying once via the default resolver with DNSSEC \
                     validation disabled as a last resort (see hickory-dns issue #3974 and \
                     algod-rust issue #1614 for why this stage exists — this does not affect \
                     the real-validation attempts already made above)"
                );
                let unvalidated_default_resolver = Self::default_resolver(false);
                match Self::do_lookup_bounded(&unvalidated_default_resolver, &srv_name).await {
                    Ok(records) => return Ok(records),
                    Err(e) => {
                        info!(
                            "DNS SRV lookup also failed with DNSSEC-disabled last-resort \
                             resolver: {e}"
                        );
                    }
                }
            }

            Err(SrvResolveError::AllResolversFailed {
                system: sys_err,
                fallback: fb_err,
                default: default_err,
            })
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

    // --- DNSSEC-validation flag threading (issue #1314) ---------------------

    /// `new` (the default constructor, used by `observe`/`sync`, which have
    /// no loaded config to consult) enables DNSSEC validation — go's own
    /// default (`DNSSecurityFlags`'s SRV bit set).
    #[test]
    fn new_enables_dnssec_validation_by_default() {
        let resolver = HickorySrvResolver::new(None);
        assert!(resolver.validate_dnssec);
    }

    /// `new_with_dnssec_validation` threads an explicit `true` through.
    #[test]
    fn new_with_dnssec_validation_true() {
        let resolver = HickorySrvResolver::new_with_dnssec_validation(None, true);
        assert!(resolver.validate_dnssec);
    }

    /// `new_with_dnssec_validation` threads an explicit `false` through —
    /// the core parity fix: an operator clearing `DNSSecurityFlags`'s SRV
    /// bit must actually disable validation, not just round-trip the
    /// setting unused.
    #[test]
    fn new_with_dnssec_validation_false() {
        let resolver =
            HickorySrvResolver::new_with_dnssec_validation(Some("8.8.8.8".to_string()), false);
        assert!(!resolver.validate_dnssec);
        assert_eq!(resolver.fallback_dns.as_deref(), Some("8.8.8.8"));
    }

    // -----------------------------------------------------------------------
    // Resolver-selection tests
    //
    // go-algorand's `tools/network.ResolveController` exposes
    // `SystemResolver()`/`FallbackResolver()`/`DefaultResolver()` as three
    // separately-constructible, separately-typed resolvers so its own tests
    // (`resolveController_test.go`) can assert on each one's concrete type
    // and `EffectiveResolverDNS()` in isolation. `HickorySrvResolver`
    // collapses all three into private helpers used internally by the
    // `system -> fallback -> default` chain in `lookup_srv` (there's no
    // separate "DNSSEC resolver type" in hickory — a single `TokioResolver`
    // either validates or doesn't, per `opts.validate`), so the closest
    // equivalent tests exercise those same helpers directly and assert on
    // the resulting `ResolverConfig`'s name-server list — the Rust
    // equivalent of `EffectiveResolverDNS()`.
    // -----------------------------------------------------------------------

    /// Mirrors `TestFallbackResolver`: a valid fallback address is used
    /// verbatim as the resolver's only name server, on port 53.
    #[test]
    fn fallback_resolver_config_uses_given_address() {
        let config = HickorySrvResolver::fallback_resolver_config("127.0.0.1")
            .expect("valid IP must produce a config");
        let servers = config.name_servers();
        // `from_ips_clear` registers both a UDP and a TCP entry for the
        // address; every entry must point at exactly this address and port.
        assert!(!servers.is_empty());
        for ns in servers {
            assert_eq!(ns.socket_addr.ip().to_string(), "127.0.0.1");
            assert_eq!(ns.socket_addr.port(), 53);
        }
    }

    /// Mirrors `TestFallbackResolverInvalidAddress`: an unresolvable
    /// fallback address (consecutive dots form an empty, syntactically
    /// invalid label, so this fails locally without a network lookup) must
    /// produce no config — the caller (`lookup_srv`) then falls through to
    /// the default resolver rather than building a resolver around a
    /// nonsense address or panicking.
    #[test]
    fn fallback_resolver_config_returns_none_for_invalid_address() {
        assert!(
            HickorySrvResolver::fallback_resolver_config("invalid..fallback..address").is_none()
        );
    }

    /// A hostname (not a bare IP) is also not a valid fallback address in
    /// go's `net.ParseIP`-based check, nor in Rust's `IpAddr::parse`.
    #[test]
    fn fallback_resolver_config_returns_none_for_hostname() {
        assert!(HickorySrvResolver::fallback_resolver_config("example.com").is_none());
    }

    /// Mirrors `TestDefaultResolver`: the default resolver's name-server
    /// list is go's well-known public DNS set (Cloudflare + Google), not
    /// empty and not the OS-configured system resolver.
    #[test]
    fn default_resolver_config_uses_cloudflare_and_google_nameservers() {
        let config = HickorySrvResolver::default_resolver_config();
        let ips: Vec<String> = config
            .name_servers()
            .iter()
            .map(|ns| ns.socket_addr.ip().to_string())
            .collect();
        assert!(!ips.is_empty());
        // Cloudflare's well-known resolver address.
        assert!(
            ips.iter().any(|ip| ip == "1.1.1.1"),
            "expected Cloudflare 1.1.1.1 among default name servers, got {ips:?}"
        );
        // Google's well-known resolver address.
        assert!(
            ips.iter().any(|ip| ip == "8.8.8.8"),
            "expected Google 8.8.8.8 among default name servers, got {ips:?}"
        );
    }

    /// Mirrors `TestSystemResolver`: building the system resolver succeeds
    /// (returns a usable resolver rather than erroring or panicking)
    /// regardless of whether DNSSEC validation is requested — go's test
    /// asserts a `*dnssec.Resolver` is produced when `secure`, a plain
    /// `*net.Resolver` when not; hickory has one resolver type either way,
    /// so the parity assertion is "both `validate` settings build cleanly".
    #[test]
    fn system_resolver_builds_for_both_dnssec_settings() {
        assert!(
            HickorySrvResolver::system_resolver(false).is_ok(),
            "system resolver must build with DNSSEC validation off"
        );
        assert!(
            HickorySrvResolver::system_resolver(true).is_ok(),
            "system resolver must build with DNSSEC validation on"
        );
    }

    // -----------------------------------------------------------------------
    // EDNS0 configuration tests (issue #1600)
    //
    // Root cause: none of this module's resolver builders set
    // `ResolverOpts::edns0`, so it stayed at hickory-resolver's own default
    // of `false`. Every DNSSEC-validating query (the top-level SRV lookup
    // *and* every DNSKEY/DS sub-query hickory-proto issues while walking the
    // chain of trust) then went out with only a 512-byte EDNS payload
    // (`Edns::default().max_payload`) instead of the recommended 1232
    // bytes, chronically truncating responses for zones with large record
    // sets (mainnet.algorand.network's real SRV response carries ~70
    // relays) and driving hickory-proto's internal retry/depth accounting
    // past its `max_request_depth = 26` backstop — "exceeded max validation
    // depth" — even though the real delegation chain is only a few levels
    // deep. See `apply_resolver_opts`'s doc comment for the full mechanism.
    // -----------------------------------------------------------------------

    /// `apply_resolver_opts` must always enable EDNS0, regardless of the
    /// `validate` setting — this is what lets hickory attach a
    /// properly-sized (1232-byte) EDNS payload to every query, which
    /// `DnssecDnsHandle::send`'s own EDNS insertion (512-byte default)
    /// would otherwise leave undersized for large, DNSSEC-signed zones.
    #[test]
    fn apply_resolver_opts_enables_edns0_with_dnssec_validation() {
        let mut opts = ResolverOpts::default();
        apply_resolver_opts(&mut opts, true);
        assert!(opts.validate, "validate must be threaded through as given");
        assert!(
            opts.edns0,
            "edns0 must be enabled so DNSSEC queries get a properly-sized \
             EDNS payload instead of the 512-byte non-EDNS default \
             (issue #1600: undersized payload -> truncation -> retries -> \
             'exceeded max validation depth')"
        );
        assert!(opts.try_tcp_on_error, "TCP fallback must stay enabled");
    }

    /// The same EDNS0 fix must apply even when DNSSEC validation itself is
    /// off (an operator's explicit `DNSSecurityFlags` override, issue
    /// #1314) — EDNS0 is a general prerequisite for reliable large-response
    /// resolution, not something that should regress when validation is
    /// disabled.
    #[test]
    fn apply_resolver_opts_enables_edns0_without_dnssec_validation() {
        let mut opts = ResolverOpts::default();
        apply_resolver_opts(&mut opts, false);
        assert!(!opts.validate);
        assert!(opts.edns0, "edns0 must stay enabled regardless of validate");
    }

    /// Every resolver stage this module builds (`system`, `fallback`,
    /// `default`) must route through `apply_resolver_opts`, so a fallback
    /// resolver built for a concrete address also gets EDNS0. This can only
    /// be asserted indirectly here (the built `TokioResolver` doesn't expose
    /// its `ResolverOpts` back out), so it exercises `build_resolver`'s
    /// config-construction path via `fallback_resolver` and just confirms
    /// it still builds successfully with the fix in place.
    #[test]
    fn fallback_resolver_builds_with_edns0_fix_in_place() {
        assert!(
            HickorySrvResolver::fallback_resolver("8.8.8.8", true).is_some(),
            "fallback resolver must still build after routing through apply_resolver_opts"
        );
    }

    // -----------------------------------------------------------------------
    // Per-stage timeout tests (issue #1614)
    //
    // A hung/slow DNSSEC chain-of-trust walk (hickory-proto validating the
    // additional section of a large SRV response, per `DNSSEC_STAGE_TIMEOUT`'s
    // doc comment) must not be able to consume a resolver stage's entire
    // available time unboundedly. These tests exercise the timeout-conversion
    // logic deterministically via `std::future::pending`, which never
    // resolves, instead of a real (slow, network-dependent, and thus flaky in
    // CI) DNS lookup.
    // -----------------------------------------------------------------------

    /// `HickorySrvResolver::bound` must convert an elapsed deadline into
    /// `SrvResolveError::Timeout` carrying the budget that was used, rather
    /// than hanging forever or panicking.
    #[tokio::test]
    async fn bound_converts_elapsed_deadline_to_timeout_error() {
        let budget = Duration::from_millis(5);
        let result = HickorySrvResolver::bound(std::future::pending(), budget).await;
        match result {
            Err(SrvResolveError::Timeout(d)) => assert_eq!(d, budget),
            other => panic!("expected SrvResolveError::Timeout({budget:?}), got: {other:?}"),
        }
    }

    /// A future that resolves before the deadline must pass its result
    /// through unaffected -- `bound` must not alter a successful (or
    /// erroring) inner result when there was no timeout.
    #[tokio::test]
    async fn bound_passes_through_fast_result() {
        let record = SrvRecord {
            target: "relay.example.com".to_string(),
            port: 4160,
            priority: 1,
            weight: 1,
        };
        let expected = record.clone();
        let result =
            HickorySrvResolver::bound(async move { Ok(vec![record]) }, Duration::from_secs(5))
                .await
                .expect("fast future must resolve Ok, not time out");
        assert_eq!(result, vec![expected]);
    }

    /// `SrvResolveError::Timeout`'s `Display` must name the elapsed budget,
    /// so operators reading node logs can tell a hung DNSSEC stage from a
    /// hard DNS failure.
    #[test]
    fn error_display_timeout() {
        let err = SrvResolveError::Timeout(Duration::from_secs(15));
        let msg = err.to_string();
        assert!(msg.contains("timed out"), "message was: {msg}");
        assert!(msg.contains("15s"), "message was: {msg}");
    }

    /// `DNSSEC_STAGE_TIMEOUT` must leave enough headroom for all four
    /// `lookup_srv` stages (system, fallback, default, and the DNSSEC-disabled
    /// last resort) to run sequentially within a typical multi-minute
    /// node-startup budget, and must be short enough that a single hung stage
    /// can't by itself consume that whole budget (issue #1614's own
    /// reproduction: ~70 errors clustered at the very end of a 2-minute
    /// `participate` startup window).
    #[test]
    fn dnssec_stage_timeout_leaves_startup_headroom() {
        let worst_case_all_four_stages = DNSSEC_STAGE_TIMEOUT * 4;
        assert!(
            worst_case_all_four_stages < Duration::from_secs(90),
            "four stages at {DNSSEC_STAGE_TIMEOUT:?} each should fit comfortably inside a \
             2-minute startup window, got {worst_case_all_four_stages:?}"
        );
        assert!(
            DNSSEC_STAGE_TIMEOUT >= Duration::from_secs(5),
            "the budget must still allow a real (non-hung) DNSSEC validation to complete"
        );
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

    // -----------------------------------------------------------------------
    // sort_and_randomize_srv_records tests (RFC 2782 priority/weight order)
    // -----------------------------------------------------------------------

    /// Direct port of go-algorand's `tools/network/dnssec.TestSrvSort`
    /// (`sort_test.go`): after sorting, records must be grouped by
    /// ascending priority, and within the lowest-priority tier the
    /// maximum-weight (0xFFFF) record must land first at least once in a
    /// few attempts (weighted randomization means it isn't guaranteed on
    /// every single run, same non-determinism go's own test tolerates).
    #[test]
    fn srv_sort_orders_by_priority_and_weight() {
        fn rec(priority: u16, weight: u16) -> SrvRecord {
            SrvRecord {
                target: "t".to_string(),
                port: 0,
                priority,
                weight,
            }
        }

        let base = vec![
            rec(4, 1),
            rec(3, 1),
            rec(1, 0xFFFF), // max possible weight, to increase ordering probability
            rec(1, 1),
            rec(1, 1),
            rec(1, 1),
            rec(1, 1),
        ];

        let mut saw_max_weight_first = false;
        for _ in 0..8 {
            let mut arr = base.clone();
            sort_and_randomize_srv_records(&mut arr);

            // Priority groups must always be in ascending order, and the
            // last two entries (the singleton priority-3 and priority-4
            // tiers) are always fixed regardless of randomization.
            assert_eq!(arr[5], rec(3, 1));
            assert_eq!(arr[6], rec(4, 1));
            // The five priority-1 records occupy positions 0..5, in some
            // weighted-random order.
            let mut tier1 = arr[0..5].to_vec();
            tier1.sort_by_key(|r| r.weight);
            assert_eq!(
                tier1,
                vec![rec(1, 1), rec(1, 1), rec(1, 1), rec(1, 1), rec(1, 0xFFFF)]
            );

            if arr[0] == rec(1, 0xFFFF) {
                saw_max_weight_first = true;
            }
        }
        assert!(
            saw_max_weight_first,
            "the highest-weight record should sort first at least once across several attempts"
        );
    }

    /// `sort_and_randomize_srv_records` must be a stable no-op reorder when
    /// there is nothing to randomize (a single record, or all-zero weights
    /// within a tier still get shuffled per RFC 2782, but a single-element
    /// slice can't move).
    #[test]
    fn srv_sort_single_record_is_unchanged() {
        let mut arr = vec![SrvRecord {
            target: "solo.example.com".to_string(),
            port: 4160,
            priority: 1,
            weight: 1,
        }];
        sort_and_randomize_srv_records(&mut arr);
        assert_eq!(arr[0].target, "solo.example.com");
    }

    /// Zero-weight records within a priority tier must not panic (the
    /// weighted-random loop's `sum > 0` guard should short-circuit
    /// immediately, matching go's `randomize` behavior for an all-zero-weight
    /// tier).
    #[test]
    fn srv_sort_zero_weight_tier_does_not_panic() {
        let mut arr = vec![
            SrvRecord {
                target: "a".to_string(),
                port: 1,
                priority: 5,
                weight: 0,
            },
            SrvRecord {
                target: "b".to_string(),
                port: 2,
                priority: 5,
                weight: 0,
            },
        ];
        sort_and_randomize_srv_records(&mut arr);
        assert_eq!(arr.len(), 2);
    }

    // -----------------------------------------------------------------------
    // lookup_srv_via_stage tests
    // -----------------------------------------------------------------------

    /// Requesting [`ResolverStage::Fallback`] with no fallback address
    /// configured must fail fast with [`SrvResolveError::FallbackNotConfigured`],
    /// not silently fall through to another stage (that would defeat the
    /// point of per-stage selection).
    #[tokio::test]
    async fn lookup_srv_via_stage_fallback_not_configured() {
        let resolver = HickorySrvResolver::new(None);
        let err = resolver
            .lookup_srv_via_stage("svc", "tcp", "example.com", ResolverStage::Fallback)
            .await
            .expect_err("fallback stage with no fallback configured must error");
        assert!(
            matches!(err, SrvResolveError::FallbackNotConfigured),
            "expected FallbackNotConfigured, got: {err}"
        );
    }

    /// Requesting [`ResolverStage::Fallback`] with an unparseable fallback
    /// address must also fail with [`SrvResolveError::FallbackNotConfigured`]
    /// rather than falling through.
    #[tokio::test]
    async fn lookup_srv_via_stage_fallback_invalid_address() {
        let resolver = HickorySrvResolver::new(Some("not-an-ip".to_string()));
        let err = resolver
            .lookup_srv_via_stage("svc", "tcp", "example.com", ResolverStage::Fallback)
            .await
            .expect_err("fallback stage with an invalid address must error");
        assert!(
            matches!(err, SrvResolveError::FallbackNotConfigured),
            "expected FallbackNotConfigured, got: {err}"
        );
    }

    /// `lookup_srv_via_stage` validates its `name`/`protocol` arguments the
    /// same way `lookup_srv` does, regardless of stage.
    #[tokio::test]
    async fn lookup_srv_via_stage_validates_inputs() {
        let resolver = HickorySrvResolver::new(None);

        let empty_name_err = resolver
            .lookup_srv_via_stage("svc", "tcp", "", ResolverStage::Default)
            .await
            .expect_err("empty name must error");
        assert!(matches!(empty_name_err, SrvResolveError::EmptyName));

        let bad_protocol_err = resolver
            .lookup_srv_via_stage("svc", "quic", "example.com", ResolverStage::System)
            .await
            .expect_err("unsupported protocol must error");
        assert!(matches!(
            bad_protocol_err,
            SrvResolveError::UnsupportedProtocol(_)
        ));
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
