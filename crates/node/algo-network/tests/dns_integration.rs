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
use algo_network::srv_resolver::{resolve_addresses, HickorySrvResolver};

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
