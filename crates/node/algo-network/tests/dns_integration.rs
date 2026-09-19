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

//! Integration tests for DNS SRV resolution against real Algorand DNS records.
//!
//! These tests resolve REAL DNS SRV records for Algorand's mainnet, testnet,
//! and backup domains.  They are NOT mocked -- they hit real DNS servers.
//!
//! # Running
//!
//! ```bash
//! ALGO_NETWORK_TESTS=1 cargo test -p algo-network --test dns_integration -- --nocapture
//! ```
//!
//! Tests skip gracefully (pass with no assertions) when `ALGO_NETWORK_TESTS`
//! is not set to `"1"`.  No `#[ignore]` attributes are used.

use std::time::Duration;

use algo_network::dns_bootstrap::parse_dns_bootstrap_array;
use algo_network::peer_role::RELAY_ROLE;
use algo_network::phonebook::Phonebook;
use algo_network::srv_resolver::{resolve_addresses, HickorySrvResolver, ResolverStage};

// ---------------------------------------------------------------------------
// Test gating
// ---------------------------------------------------------------------------

/// Returns `true` if network tests should be skipped.
///
/// Tests are enabled when `ALGO_NETWORK_TESTS=1` is set in the environment.
fn skip_unless_network_tests() -> bool {
    std::env::var("ALGO_NETWORK_TESTS").map_or(true, |v| v != "1")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Resolve mainnet relay SRV records from
/// `_algobootstrap._tcp.mainnet.algorand.network`.
///
/// Asserts at least one relay address is returned and that each address
/// matches the `host:port` format.
#[tokio::test]
async fn test_mainnet_relay_srv_resolution() {
    if skip_unless_network_tests() {
        eprintln!("SKIPPED: ALGO_NETWORK_TESTS != 1");
        return;
    }

    let resolver = HickorySrvResolver::new(None);
    let result = resolve_addresses(
        &resolver,
        "algobootstrap",
        "tcp",
        "mainnet.algorand.network",
    )
    .await;

    let addrs = result.expect("mainnet relay SRV lookup should succeed");

    assert!(
        !addrs.is_empty(),
        "mainnet relay SRV should return at least one address"
    );

    for addr in &addrs {
        assert!(
            addr.contains(':'),
            "address should be host:port format, got: {addr}"
        );
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        assert_eq!(parts.len(), 2, "expected host:port, got: {addr}");
        let port_str = parts[0];
        let _port: u16 = port_str
            .parse()
            .unwrap_or_else(|_| panic!("port should be a u16, got: {port_str}"));
    }

    eprintln!("mainnet relay addresses ({} total):", addrs.len());
    for addr in &addrs {
        eprintln!("  {addr}");
    }
}

/// Resolve mainnet archival SRV records from
/// `_archive._tcp.mainnet.algorand.network`.
///
/// Asserts at least one archival address is returned.
#[tokio::test]
async fn test_mainnet_archival_srv_resolution() {
    if skip_unless_network_tests() {
        eprintln!("SKIPPED: ALGO_NETWORK_TESTS != 1");
        return;
    }

    let resolver = HickorySrvResolver::new(None);
    let result = resolve_addresses(&resolver, "archive", "tcp", "mainnet.algorand.network").await;

    let addrs = result.expect("mainnet archival SRV lookup should succeed");

    assert!(
        !addrs.is_empty(),
        "mainnet archival SRV should return at least one address"
    );

    for addr in &addrs {
        assert!(
            addr.contains(':'),
            "address should be host:port format, got: {addr}"
        );
    }

    eprintln!("mainnet archival addresses ({} total):", addrs.len());
    for addr in &addrs {
        eprintln!("  {addr}");
    }
}

/// Resolve testnet relay SRV records from
/// `_algobootstrap._tcp.testnet.algorand.network`.
///
/// Asserts at least one relay address is returned.
#[tokio::test]
async fn test_testnet_relay_srv_resolution() {
    if skip_unless_network_tests() {
        eprintln!("SKIPPED: ALGO_NETWORK_TESTS != 1");
        return;
    }

    let resolver = HickorySrvResolver::new(None);
    let result = resolve_addresses(
        &resolver,
        "algobootstrap",
        "tcp",
        "testnet.algorand.network",
    )
    .await;

    let addrs = result.expect("testnet relay SRV lookup should succeed");

    assert!(
        !addrs.is_empty(),
        "testnet relay SRV should return at least one address"
    );

    for addr in &addrs {
        assert!(
            addr.contains(':'),
            "address should be host:port format, got: {addr}"
        );
    }

    eprintln!("testnet relay addresses ({} total):", addrs.len());
    for addr in &addrs {
        eprintln!("  {addr}");
    }
}

/// Resolve relay SRV records from the backup domain
/// `_algobootstrap._tcp.mainnet.algorand.net`.
///
/// The backup domain should also return valid relay addresses.
#[tokio::test]
async fn test_backup_domain_relay_resolution() {
    if skip_unless_network_tests() {
        eprintln!("SKIPPED: ALGO_NETWORK_TESTS != 1");
        return;
    }

    let resolver = HickorySrvResolver::new(None);
    let result = resolve_addresses(&resolver, "algobootstrap", "tcp", "mainnet.algorand.net").await;

    let addrs = result.expect("backup domain relay SRV lookup should succeed");

    assert!(
        !addrs.is_empty(),
        "backup domain relay SRV should return at least one address"
    );

    for addr in &addrs {
        assert!(
            addr.contains(':'),
            "address should be host:port format, got: {addr}"
        );
    }

    eprintln!("backup domain relay addresses ({} total):", addrs.len());
    for addr in &addrs {
        eprintln!("  {addr}");
    }
}

/// End-to-end flow: parse the default DNSBootstrapID template, resolve SRV
/// records for both primary and backup domains, and populate a phonebook.
///
/// This exercises the full discovery pipeline from DNS bootstrap config
/// through SRV resolution to phonebook population.
#[tokio::test]
async fn test_dns_bootstrap_to_phonebook_flow() {
    if skip_unless_network_tests() {
        eprintln!("SKIPPED: ALGO_NETWORK_TESTS != 1");
        return;
    }

    // 1. Parse the default DNSBootstrapID template for mainnet.
    //    The <network> macro is substituted with "mainnet" (the genesis
    //    network name, without the version suffix).
    let template = "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)";
    let network = "mainnet";
    let bootstraps =
        parse_dns_bootstrap_array(template, network, true).expect("template should parse");

    assert!(
        !bootstraps.is_empty(),
        "should have at least one bootstrap entry"
    );
    eprintln!("parsed {} bootstrap entries", bootstraps.len());

    // 2. Create a phonebook and resolver.
    let phonebook = Phonebook::new(10, Duration::from_secs(60));
    let resolver = HickorySrvResolver::new(None);

    // 3. For each bootstrap entry, resolve SRV records and populate the phonebook.
    let mut total_relay_addrs = 0usize;

    for bootstrap in &bootstraps {
        // Resolve primary domain.
        if !bootstrap.primary_srv_bootstrap.is_empty() {
            eprintln!(
                "resolving primary: _algobootstrap._tcp.{}",
                bootstrap.primary_srv_bootstrap
            );
            match resolve_addresses(
                &resolver,
                "algobootstrap",
                "tcp",
                &bootstrap.primary_srv_bootstrap,
            )
            .await
            {
                Ok(addrs) => {
                    eprintln!("  primary returned {} addresses", addrs.len());
                    phonebook.replace_peer_list(
                        &addrs,
                        &bootstrap.primary_srv_bootstrap,
                        RELAY_ROLE,
                    );
                    total_relay_addrs += addrs.len();
                }
                Err(e) => {
                    eprintln!("  primary resolution failed (non-fatal): {e}");
                }
            }
        }

        // Resolve backup domain.
        if !bootstrap.backup_srv_bootstrap.is_empty() {
            eprintln!(
                "resolving backup: _algobootstrap._tcp.{}",
                bootstrap.backup_srv_bootstrap
            );
            match resolve_addresses(
                &resolver,
                "algobootstrap",
                "tcp",
                &bootstrap.backup_srv_bootstrap,
            )
            .await
            {
                Ok(addrs) => {
                    eprintln!("  backup returned {} addresses", addrs.len());
                    phonebook.replace_peer_list(
                        &addrs,
                        &bootstrap.backup_srv_bootstrap,
                        RELAY_ROLE,
                    );
                    total_relay_addrs += addrs.len();
                }
                Err(e) => {
                    eprintln!("  backup resolution failed (non-fatal): {e}");
                }
            }
        }
    }

    // 4. Assert the phonebook has relay addresses.
    let relay_addrs = phonebook.get_addresses(usize::MAX, RELAY_ROLE);
    eprintln!(
        "phonebook contains {} unique relay addresses (from {} total resolved)",
        relay_addrs.len(),
        total_relay_addrs
    );

    assert!(
        !relay_addrs.is_empty(),
        "phonebook should contain at least one relay address after DNS bootstrap"
    );

    for addr in &relay_addrs {
        eprintln!("  phonebook relay: {addr}");
    }
}

/// Resolving a clearly bogus domain should return an error or empty result,
/// not panic.
#[tokio::test]
async fn test_nonexistent_domain_returns_empty_or_error() {
    if skip_unless_network_tests() {
        eprintln!("SKIPPED: ALGO_NETWORK_TESTS != 1");
        return;
    }

    let resolver = HickorySrvResolver::new(None);
    let result = resolve_addresses(
        &resolver,
        "algobootstrap",
        "tcp",
        "this-domain-does-not-exist-12345.invalid",
    )
    .await;

    match result {
        Ok(addrs) => {
            // Empty result is acceptable for a nonexistent domain.
            assert!(
                addrs.is_empty(),
                "bogus domain should return empty, got {} addresses",
                addrs.len()
            );
            eprintln!("bogus domain returned empty (Ok with 0 addresses)");
        }
        Err(e) => {
            // Error is the expected path for NXDOMAIN.
            eprintln!("bogus domain returned error (expected): {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Per-stage resolution tests (`lookup_srv_via_stage`)
//
// These mirror go-algorand's `tools/network/resolver_test.go` tests, which
// each force resolution through one specific resolver and assert on
// `Resolver.EffectiveResolverDNS()`. `HickorySrvResolver` has no equivalent
// "effective DNS" accessor (a `TokioResolver` doesn't expose which name
// server actually answered), so these tests instead assert on the
// success/failure of resolution *forced through* the named stage, which is
// the externally-observable half of go's assertion.
// ---------------------------------------------------------------------------

/// Mirrors `TestResolverWithDefaultDNSResolution`: with no fallback
/// configured, forcing resolution through [`ResolverStage::Default`] (the
/// well-known Cloudflare/Google resolver, go's `defaultDNSAddress` == 8.8.8.8
/// equivalent) against a real SRV record succeeds.
#[tokio::test]
async fn test_resolver_with_default_dns_resolution() {
    if skip_unless_network_tests() {
        eprintln!("SKIPPED: ALGO_NETWORK_TESTS != 1");
        return;
    }

    let resolver = HickorySrvResolver::new(None);
    let records = resolver
        .lookup_srv_via_stage(
            "algobootstrap",
            "tcp",
            "mainnet.algorand.network",
            ResolverStage::Default,
        )
        .await
        .expect("default-resolver SRV lookup should succeed");

    assert!(
        !records.is_empty(),
        "default resolver should return at least one SRV record"
    );
}

/// Mirrors `TestResolverWithCloudflareDNSResolution`: a resolver whose
/// fallback is pinned to Cloudflare's secondary DNS server (`1.0.0.1` — go's
/// own comment notes CI providers have blocked `1.1.1.1`) resolves a real SRV
/// record when forced through [`ResolverStage::Fallback`].
#[tokio::test]
async fn test_resolver_with_cloudflare_dns_resolution() {
    if skip_unless_network_tests() {
        eprintln!("SKIPPED: ALGO_NETWORK_TESTS != 1");
        return;
    }

    let resolver = HickorySrvResolver::new(Some("1.0.0.1".to_string()));
    let records = resolver
        .lookup_srv_via_stage(
            "algobootstrap",
            "tcp",
            "mainnet.algorand.network",
            ResolverStage::Fallback,
        )
        .await
        .expect("Cloudflare fallback-resolver SRV lookup should succeed");

    assert!(
        !records.is_empty(),
        "Cloudflare fallback resolver should return at least one SRV record"
    );
}

/// Mirrors `TestResolverWithInvalidDNSResolution`: a resolver whose fallback
/// is pinned to an unreachable IP (`255.255.128.1`, go's own dummy address)
/// fails rather than hanging, within a short timeout.
#[tokio::test]
async fn test_resolver_with_invalid_dns_resolution() {
    if skip_unless_network_tests() {
        eprintln!("SKIPPED: ALGO_NETWORK_TESTS != 1");
        return;
    }

    let resolver = HickorySrvResolver::new(Some("255.255.128.1".to_string()));
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        resolver.lookup_srv_via_stage(
            "algobootstrap",
            "tcp",
            "mainnet.algorand.network",
            ResolverStage::Fallback,
        ),
    )
    .await;

    match result {
        // The lookup itself returned in time -- it must have errored (an
        // unreachable resolver can never produce a valid answer).
        Ok(lookup_result) => {
            assert!(
                lookup_result.is_err(),
                "lookup via an unreachable fallback resolver should fail, got: {lookup_result:?}"
            );
        }
        // The outer `tokio::time::timeout` fired first -- also an acceptable
        // "did not succeed" outcome, matching go's own context-timeout-based
        // test (a 100ms context timeout that also just needs `err != nil`).
        Err(_) => {
            eprintln!("lookup via unreachable fallback resolver timed out (expected)");
        }
    }
}

/// Mirrors `TestRealNamesWithResolver` (itself `t.Skip()`-disabled in
/// go-algorand's own suite -- "skip real network tests in autotest"): forcing
/// resolution through each named stage in turn (system, fallback pinned to
/// `1.1.1.1`, default) all succeed for a real SRV record, and a fallback
/// pinned to an unreachable private-range IP (`192.168.12.34`, go's own
/// dummy address) errors.
#[tokio::test]
async fn test_real_names_with_resolver_per_stage() {
    if skip_unless_network_tests() {
        eprintln!("SKIPPED: ALGO_NETWORK_TESTS != 1");
        return;
    }

    let name = "mainnet.algorand.network";

    // System resolver: OS-configured DNS should resolve the real record.
    let system_only = HickorySrvResolver::new(None);
    let system_records = system_only
        .lookup_srv_via_stage("algobootstrap", "tcp", name, ResolverStage::System)
        .await
        .expect("system resolver should resolve a real SRV record");
    assert!(!system_records.is_empty());

    for validate_dnssec in [false, true] {
        let resolver = HickorySrvResolver::new_with_dnssec_validation(
            Some("1.1.1.1".to_string()),
            validate_dnssec,
        );

        let fallback_records = resolver
            .lookup_srv_via_stage("algobootstrap", "tcp", name, ResolverStage::Fallback)
            .await
            .unwrap_or_else(|e| {
                panic!("fallback resolver (dnssec={validate_dnssec}) should succeed: {e}")
            });
        assert!(!fallback_records.is_empty());

        let default_records = resolver
            .lookup_srv_via_stage("algobootstrap", "tcp", name, ResolverStage::Default)
            .await
            .unwrap_or_else(|e| {
                panic!("default resolver (dnssec={validate_dnssec}) should succeed: {e}")
            });
        assert!(!default_records.is_empty());

        // An unreachable private-range fallback address must error out
        // (within a bounded timeout) rather than hang or silently succeed.
        let unreachable = HickorySrvResolver::new_with_dnssec_validation(
            Some("192.168.12.34".to_string()),
            validate_dnssec,
        );
        let unreachable_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            unreachable.lookup_srv_via_stage("algobootstrap", "tcp", name, ResolverStage::Fallback),
        )
        .await;
        match unreachable_result {
            Ok(lookup_result) => assert!(
                lookup_result.is_err(),
                "lookup via unreachable private-range fallback should fail"
            ),
            Err(_) => eprintln!(
                "lookup via unreachable private-range fallback (dnssec={validate_dnssec}) timed out (expected)"
            ),
        }
    }
}
