//! Discovery orchestrator for peer discovery via DNS SRV records.
//!
//! Combines DNS SRV resolution with phonebook management, matching
//! go-algorand's `wsNetwork.go` functions `refreshRelayArchivePhonebookAddresses()`,
//! `getDNSAddrs()`, `mergePrimarySecondaryAddressSlices()`, and
//! `updatePhonebookAddresses()`.

use std::sync::Arc;

use regex::Regex;
use tracing::{debug, info, warn};

use crate::dns_bootstrap::{parse_dns_bootstrap_array, DnsBootstrap, DnsBootstrapError};
use crate::peer_role::{Role, ARCHIVAL_ROLE, RELAY_ROLE};
use crate::phonebook::Phonebook;
use crate::srv_resolver::{resolve_addresses, SrvResolver};

/// Discovery orchestrator that combines DNS SRV resolution with phonebook
/// management.
///
/// On construction, the DNS bootstrap ID template is parsed into one or more
/// [`DnsBootstrap`] entries.  The [`refresh_phonebook_addresses`] method then
/// iterates over those entries, resolves SRV records for relay and archival
/// peers, merges primary and backup results (with optional deduplication),
/// and updates the shared [`Phonebook`].
///
/// [`refresh_phonebook_addresses`]: Discovery::refresh_phonebook_addresses
pub struct Discovery {
    /// Shared phonebook for storing discovered peer addresses.
    phonebook: Arc<Phonebook>,

    /// DNS SRV resolver (trait object for testability).
    resolver: Box<dyn SrvResolver>,

    /// Parsed DNS bootstrap entries derived from the bootstrap ID template.
    bootstrap_entries: Vec<DnsBootstrap>,

    /// Network identifier (e.g. `"mainnet"`, `"testnet"`), used as the
    /// `network_name` parameter when updating the phonebook.
    network_id: String,
}

impl Discovery {
    /// Creates a new `Discovery` orchestrator.
    ///
    /// # Arguments
    ///
    /// * `phonebook` - Shared phonebook to update with discovered peers.
    /// * `resolver` - DNS SRV resolver implementation.
    /// * `dns_bootstrap_id` - Bootstrap ID template string (may contain
    ///   `<network>` macros and semicolon-separated entries).
    /// * `network_id` - Network identifier for `<network>` substitution and
    ///   phonebook network-name tagging.
    /// * `default_template_overridden` - When `true`, the caller has explicitly
    ///   overridden the default bootstrap template, so hardcoded network
    ///   overrides for devnet/betanet/alphanet are bypassed.
    ///
    /// # Errors
    ///
    /// Returns [`DnsBootstrapError`] if the bootstrap ID template cannot be
    /// parsed.
    pub fn new(
        phonebook: Arc<Phonebook>,
        resolver: Box<dyn SrvResolver>,
        dns_bootstrap_id: &str,
        network_id: &str,
        default_template_overridden: bool,
    ) -> Result<Self, DnsBootstrapError> {
        let bootstrap_entries =
            parse_dns_bootstrap_array(dns_bootstrap_id, network_id, default_template_overridden)?;
        info!(
            network = network_id,
            count = bootstrap_entries.len(),
            "parsed DNS bootstrap entries"
        );
        Ok(Self {
            phonebook,
            resolver,
            bootstrap_entries,
            network_id: network_id.to_string(),
        })
    }

    /// Resolves relay and archival peer addresses from DNS SRV records for the
    /// given domain.
    ///
    /// Returns `(relay_addresses, archival_addresses)`.  On error, logs a
    /// warning and returns an empty vector for the failed lookup.
    ///
    /// Mirrors go-algorand's `getDNSAddrs` in `wsNetwork.go`.
    pub async fn get_dns_addrs(&self, domain: &str) -> (Vec<String>, Vec<String>) {
        // Resolve relay addresses via "_algobootstrap._tcp.<domain>".
        let relay_addresses =
            match resolve_addresses(self.resolver.as_ref(), "algobootstrap", "tcp", domain).await {
                Ok(addrs) => {
                    debug!(domain, count = addrs.len(), "resolved relay SRV records");
                    addrs
                }
                Err(e) => {
                    warn!(domain, error = %e, "failed to resolve relay SRV records");
                    Vec::new()
                }
            };

        // Resolve archival addresses via "_archive._tcp.<domain>".
        let archival_addresses =
            match resolve_addresses(self.resolver.as_ref(), "archive", "tcp", domain).await {
                Ok(addrs) => {
                    debug!(domain, count = addrs.len(), "resolved archival SRV records");
                    addrs
                }
                Err(e) => {
                    warn!(domain, error = %e, "failed to resolve archival SRV records");
                    Vec::new()
                }
            };

        (relay_addresses, archival_addresses)
    }

    /// Merges primary and secondary (backup) address slices with optional
    /// deduplication.
    ///
    /// If `dedup_exp` is `None`, the two slices are simply concatenated.  With
    /// a dedup regex, each address is normalised to lowercase and its "prefix
    /// key" is computed by removing the regex match.  Primary addresses take
    /// priority: if two addresses produce the same prefix key, the primary
    /// address is kept and the secondary is discarded.
    ///
    /// Mirrors go-algorand's `mergePrimarySecondaryAddressSlices`.
    pub fn merge_primary_secondary(
        primary: &[String],
        secondary: &[String],
        dedup_exp: Option<&Regex>,
    ) -> Vec<String> {
        let dedup_re = match dedup_exp {
            Some(re) => re,
            None => {
                // No dedup regex: simple concatenation.
                let mut merged = Vec::with_capacity(primary.len() + secondary.len());
                merged.extend_from_slice(primary);
                merged.extend_from_slice(secondary);
                return merged;
            }
        };

        // Deduplicate by prefix key.  Primary addresses take priority.
        let mut prefix_to_value = std::collections::HashMap::new();
        // Track insertion order so we return deterministic results matching Go.
        let mut order = Vec::new();

        for addr in primary {
            let normalized = addr.to_lowercase();
            let pfx_key = dedup_re.replace_all(&normalized, "").to_string();
            if !prefix_to_value.contains_key(&pfx_key) {
                prefix_to_value.insert(pfx_key.clone(), normalized);
                order.push(pfx_key);
            }
        }

        for addr in secondary {
            let normalized = addr.to_lowercase();
            let pfx_key = dedup_re.replace_all(&normalized, "").to_string();
            if !prefix_to_value.contains_key(&pfx_key) {
                prefix_to_value.insert(pfx_key.clone(), normalized);
                order.push(pfx_key);
            }
        }

        order
            .into_iter()
            .filter_map(|k| prefix_to_value.remove(&k))
            .collect()
    }

    /// Updates the phonebook with the given relay and archival addresses.
    ///
    /// Only non-empty address lists trigger a phonebook update.  Mirrors
    /// go-algorand's `updatePhonebookAddresses`.
    fn update_phonebook_addresses(&self, relay_addrs: &[String], archival_addrs: &[String]) {
        if !relay_addrs.is_empty() {
            self.phonebook
                .replace_peer_list(relay_addrs, &self.network_id, RELAY_ROLE);
            info!(
                count = relay_addrs.len(),
                network = self.network_id,
                "updated phonebook with relay addresses"
            );
        }
        if !archival_addrs.is_empty() {
            self.phonebook
                .replace_peer_list(archival_addrs, &self.network_id, ARCHIVAL_ROLE);
            info!(
                count = archival_addrs.len(),
                network = self.network_id,
                "updated phonebook with archival addresses"
            );
        }
    }

    /// Main orchestration method: iterates over all bootstrap entries,
    /// resolves primary (and optional backup) DNS SRV records, merges them
    /// with deduplication, and updates the shared phonebook.
    ///
    /// Mirrors go-algorand's `refreshRelayArchivePhonebookAddresses`.
    pub async fn refresh_phonebook_addresses(&self) {
        for entry in &self.bootstrap_entries {
            let (primary_relay, primary_archival) =
                self.get_dns_addrs(&entry.primary_srv_bootstrap).await;

            if !entry.backup_srv_bootstrap.is_empty() {
                let (backup_relay, backup_archival) =
                    self.get_dns_addrs(&entry.backup_srv_bootstrap).await;

                let deduped_relay = Self::merge_primary_secondary(
                    &primary_relay,
                    &backup_relay,
                    entry.dedup_exp.as_ref(),
                );
                let deduped_archival = Self::merge_primary_secondary(
                    &primary_archival,
                    &backup_archival,
                    entry.dedup_exp.as_ref(),
                );

                self.update_phonebook_addresses(&deduped_relay, &deduped_archival);
            } else {
                self.update_phonebook_addresses(&primary_relay, &primary_archival);
            }
        }
    }

    /// Adds persistent peers to the phonebook.
    ///
    /// Persistent peers survive [`Phonebook::replace_peer_list`] calls and are
    /// always returned by address queries.
    pub fn add_persistent_peers(&self, addresses: &[String], network_name: &str, role: Role) {
        self.phonebook
            .add_persistent_peers(addresses, network_name, role);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_role::{ARCHIVAL_ROLE, RELAY_ROLE};
    use crate::srv_resolver::{SrvRecord, SrvResolveError};
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Duration;

    // -----------------------------------------------------------------------
    // Mock resolver for discovery tests
    // -----------------------------------------------------------------------

    /// A mock [`SrvResolver`] that returns different records based on the
    /// service name ("algobootstrap" vs "archive").
    struct MockDiscoveryResolver {
        /// Map from `(service, domain)` to the records to return.
        records: HashMap<(String, String), Vec<SrvRecord>>,
    }

    impl MockDiscoveryResolver {
        fn new() -> Self {
            Self {
                records: HashMap::new(),
            }
        }

        fn add_records(&mut self, service: &str, domain: &str, records: Vec<SrvRecord>) {
            self.records
                .insert((service.to_string(), domain.to_string()), records);
        }
    }

    impl SrvResolver for MockDiscoveryResolver {
        fn lookup_srv(
            &self,
            service: &str,
            _protocol: &str,
            name: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<SrvRecord>, SrvResolveError>> + Send + '_>>
        {
            let key = (service.to_string(), name.to_string());
            let result = self.records.get(&key).cloned().unwrap_or_default();
            Box::pin(async move { Ok(result) })
        }
    }

    /// A mock resolver that always returns an error.
    struct FailingResolver;

    impl SrvResolver for FailingResolver {
        fn lookup_srv(
            &self,
            _service: &str,
            _protocol: &str,
            _name: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<SrvRecord>, SrvResolveError>> + Send + '_>>
        {
            Box::pin(async { Err(SrvResolveError::EmptyName) })
        }
    }

    // -----------------------------------------------------------------------
    // merge_primary_secondary tests
    // -----------------------------------------------------------------------

    #[test]
    fn merge_no_dedup_concatenates() {
        let primary = vec![
            "a.example.com:4160".to_string(),
            "b.example.com:4160".to_string(),
        ];
        let secondary = vec!["c.example.com:4160".to_string()];

        let result = Discovery::merge_primary_secondary(&primary, &secondary, None);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "a.example.com:4160");
        assert_eq!(result[1], "b.example.com:4160");
        assert_eq!(result[2], "c.example.com:4160");
    }

    #[test]
    fn merge_with_dedup_primary_wins() {
        // Simulate mainnet dedup: primary is *.algorand.network, backup is
        // *.algorand.net.  The dedup regex strips the domain suffix.
        let dedup = Regex::new(r"(algorand-mainnet\.(network|net))").unwrap();

        let primary = vec![
            "r1.algorand-mainnet.network:4160".to_string(),
            "r2.algorand-mainnet.network:4160".to_string(),
        ];
        let secondary = vec![
            "r1.algorand-mainnet.net:4160".to_string(), // same prefix as primary r1
            "r3.algorand-mainnet.net:4160".to_string(), // unique
        ];

        let result = Discovery::merge_primary_secondary(&primary, &secondary, Some(&dedup));

        // r1 from primary wins, r2 from primary kept, r3 from secondary added.
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"r1.algorand-mainnet.network:4160".to_string()));
        assert!(result.contains(&"r2.algorand-mainnet.network:4160".to_string()));
        assert!(result.contains(&"r3.algorand-mainnet.net:4160".to_string()));
        // The duplicate r1 from secondary should NOT be present.
        assert!(!result.contains(&"r1.algorand-mainnet.net:4160".to_string()));
    }

    #[test]
    fn merge_with_dedup_normalizes_case() {
        // Use (network|net) order so the longer alternative matches first,
        // matching the real mainnet dedup pattern.
        let dedup = Regex::new(r"(algorand\.(network|net))").unwrap();

        let primary = vec!["R1.ALGORAND.NETWORK:4160".to_string()];
        let secondary = vec!["r1.algorand.net:4160".to_string()];

        let result = Discovery::merge_primary_secondary(&primary, &secondary, Some(&dedup));

        // Both normalize to "r1.:4160" as the prefix key, so primary wins.
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "r1.algorand.network:4160"); // lowercased primary
    }

    #[test]
    fn merge_empty_slices() {
        let result = Discovery::merge_primary_secondary(&[], &[], None);
        assert!(result.is_empty());

        let dedup = Regex::new(r"\.example\.com").unwrap();
        let result = Discovery::merge_primary_secondary(&[], &[], Some(&dedup));
        assert!(result.is_empty());
    }

    #[test]
    fn merge_primary_only() {
        let primary = vec!["a:1".to_string(), "b:2".to_string()];
        let result = Discovery::merge_primary_secondary(&primary, &[], None);
        assert_eq!(result, primary);
    }

    #[test]
    fn merge_secondary_only() {
        let secondary = vec!["c:3".to_string(), "d:4".to_string()];
        let result = Discovery::merge_primary_secondary(&[], &secondary, None);
        assert_eq!(result, secondary);
    }

    #[test]
    fn merge_dedup_preserves_order() {
        let dedup = Regex::new(r"(\.suffix)").unwrap();

        let primary = vec!["a.suffix:1".to_string(), "b.suffix:2".to_string()];
        let secondary = vec!["c.suffix:3".to_string(), "d.suffix:4".to_string()];

        let result = Discovery::merge_primary_secondary(&primary, &secondary, Some(&dedup));

        // All have unique prefix keys, so order should be primary then secondary.
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], "a.suffix:1");
        assert_eq!(result[1], "b.suffix:2");
        assert_eq!(result[2], "c.suffix:3");
        assert_eq!(result[3], "d.suffix:4");
    }

    // -----------------------------------------------------------------------
    // Discovery::new tests
    // -----------------------------------------------------------------------

    #[test]
    fn new_parses_bootstrap_entries() {
        let pb = Arc::new(Phonebook::new(1, Duration::from_secs(1)));
        let resolver = MockDiscoveryResolver::new();
        let discovery = Discovery::new(
            pb,
            Box::new(resolver),
            "<network>.algorand.network",
            "mainnet",
            false,
        )
        .unwrap();

        assert_eq!(discovery.bootstrap_entries.len(), 1);
        assert_eq!(
            discovery.bootstrap_entries[0].primary_srv_bootstrap,
            "mainnet.algorand.network"
        );
        assert_eq!(discovery.network_id, "mainnet");
    }

    #[test]
    fn new_parses_multiple_entries() {
        let pb = Arc::new(Phonebook::new(1, Duration::from_secs(1)));
        let resolver = MockDiscoveryResolver::new();
        let discovery = Discovery::new(
            pb,
            Box::new(resolver),
            "<network>.algorand.network;<network>.algorand.net",
            "testnet",
            false,
        )
        .unwrap();

        assert_eq!(discovery.bootstrap_entries.len(), 2);
    }

    #[test]
    fn new_returns_error_for_invalid_template() {
        let pb = Arc::new(Phonebook::new(1, Duration::from_secs(1)));
        let resolver = MockDiscoveryResolver::new();
        // A bootstrap ID with invalid dedup regex should fail.
        let result = Discovery::new(
            pb,
            Box::new(resolver),
            "<network>.example.com?backup=<network>.backup.com&dedup=<name>.((invalid",
            "mainnet",
            false,
        );
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // get_dns_addrs tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_dns_addrs_returns_relay_and_archival() {
        let mut resolver = MockDiscoveryResolver::new();
        resolver.add_records(
            "algobootstrap",
            "mainnet.algorand.network",
            vec![SrvRecord {
                target: "relay1.algorand.network".to_string(),
                port: 4160,
                priority: 1,
                weight: 1,
            }],
        );
        resolver.add_records(
            "archive",
            "mainnet.algorand.network",
            vec![SrvRecord {
                target: "archival1.algorand.network".to_string(),
                port: 4160,
                priority: 1,
                weight: 1,
            }],
        );

        let pb = Arc::new(Phonebook::new(1, Duration::from_secs(1)));
        let discovery = Discovery::new(
            pb,
            Box::new(resolver),
            "<network>.algorand.network",
            "mainnet",
            false,
        )
        .unwrap();

        let (relays, archivals) = discovery.get_dns_addrs("mainnet.algorand.network").await;

        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0], "relay1.algorand.network:4160");
        assert_eq!(archivals.len(), 1);
        assert_eq!(archivals[0], "archival1.algorand.network:4160");
    }

    #[tokio::test]
    async fn get_dns_addrs_returns_empty_on_error() {
        let pb = Arc::new(Phonebook::new(1, Duration::from_secs(1)));
        let resolver = FailingResolver;
        let discovery = Discovery::new(
            pb,
            Box::new(resolver),
            "<network>.algorand.network",
            "mainnet",
            false,
        )
        .unwrap();

        let (relays, archivals) = discovery.get_dns_addrs("mainnet.algorand.network").await;

        assert!(relays.is_empty());
        assert!(archivals.is_empty());
    }

    // -----------------------------------------------------------------------
    // refresh_phonebook_addresses tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn refresh_updates_phonebook_with_primary_only() {
        let mut resolver = MockDiscoveryResolver::new();
        resolver.add_records(
            "algobootstrap",
            "mainnet.algorand.network",
            vec![
                SrvRecord {
                    target: "relay1.algorand.network".to_string(),
                    port: 4160,
                    priority: 1,
                    weight: 1,
                },
                SrvRecord {
                    target: "relay2.algorand.network".to_string(),
                    port: 4160,
                    priority: 1,
                    weight: 1,
                },
            ],
        );
        resolver.add_records(
            "archive",
            "mainnet.algorand.network",
            vec![SrvRecord {
                target: "archival1.algorand.network".to_string(),
                port: 4160,
                priority: 1,
                weight: 1,
            }],
        );

        let pb = Arc::new(Phonebook::new(1, Duration::from_secs(1)));
        let discovery = Discovery::new(
            pb.clone(),
            Box::new(resolver),
            "<network>.algorand.network",
            "mainnet",
            false,
        )
        .unwrap();

        discovery.refresh_phonebook_addresses().await;

        let mut relays = pb.get_addresses(10, RELAY_ROLE);
        relays.sort();
        assert_eq!(relays.len(), 2);
        assert_eq!(relays[0], "relay1.algorand.network:4160");
        assert_eq!(relays[1], "relay2.algorand.network:4160");

        let archivals = pb.get_addresses(10, ARCHIVAL_ROLE);
        assert_eq!(archivals.len(), 1);
        assert_eq!(archivals[0], "archival1.algorand.network:4160");
    }

    #[tokio::test]
    async fn refresh_with_backup_and_dedup() {
        let mut resolver = MockDiscoveryResolver::new();

        // Primary: mainnet.algorand.network
        resolver.add_records(
            "algobootstrap",
            "mainnet.algorand.network",
            vec![SrvRecord {
                target: "r1.algorand-mainnet.network".to_string(),
                port: 4160,
                priority: 1,
                weight: 1,
            }],
        );
        resolver.add_records("archive", "mainnet.algorand.network", vec![]);

        // Backup: mainnet.algorand.net
        resolver.add_records(
            "algobootstrap",
            "mainnet.algorand.net",
            vec![
                SrvRecord {
                    target: "r1.algorand-mainnet.net".to_string(), // duplicate of primary r1
                    port: 4160,
                    priority: 1,
                    weight: 1,
                },
                SrvRecord {
                    target: "r2.algorand-mainnet.net".to_string(), // unique
                    port: 4160,
                    priority: 1,
                    weight: 1,
                },
            ],
        );
        resolver.add_records("archive", "mainnet.algorand.net", vec![]);

        let pb = Arc::new(Phonebook::new(1, Duration::from_secs(1)));

        // Use the full default template with backup + dedup.
        let template = "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)";
        let discovery =
            Discovery::new(pb.clone(), Box::new(resolver), template, "mainnet", false).unwrap();

        discovery.refresh_phonebook_addresses().await;

        let mut relays = pb.get_addresses(10, RELAY_ROLE);
        relays.sort();

        // r1 from primary should win over r1 from backup (same prefix key).
        // r2 from backup should be included.
        assert_eq!(relays.len(), 2);
        assert!(relays.contains(&"r1.algorand-mainnet.network:4160".to_string()));
        assert!(relays.contains(&"r2.algorand-mainnet.net:4160".to_string()));
    }

    #[tokio::test]
    async fn refresh_empty_results_do_not_clear_phonebook() {
        let pb = Arc::new(Phonebook::new(1, Duration::from_secs(1)));

        // Pre-populate the phonebook.
        pb.replace_peer_list(&["existing-relay:4160".to_string()], "mainnet", RELAY_ROLE);

        // Create discovery with a resolver that returns no records.
        let resolver = MockDiscoveryResolver::new();
        let discovery = Discovery::new(
            pb.clone(),
            Box::new(resolver),
            "<network>.algorand.network",
            "mainnet",
            false,
        )
        .unwrap();

        discovery.refresh_phonebook_addresses().await;

        // The phonebook should NOT have been cleared because
        // update_phonebook_addresses skips empty lists.
        let relays = pb.get_addresses(10, RELAY_ROLE);
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0], "existing-relay:4160");
    }

    // -----------------------------------------------------------------------
    // add_persistent_peers tests
    // -----------------------------------------------------------------------

    #[test]
    fn add_persistent_peers_delegates_to_phonebook() {
        let pb = Arc::new(Phonebook::new(1, Duration::from_secs(1)));
        let resolver = MockDiscoveryResolver::new();
        let discovery = Discovery::new(
            pb.clone(),
            Box::new(resolver),
            "<network>.algorand.network",
            "mainnet",
            false,
        )
        .unwrap();

        let peers = vec!["persistent-relay:4160".to_string()];
        discovery.add_persistent_peers(&peers, "mainnet", RELAY_ROLE);

        let addrs = pb.get_addresses(10, RELAY_ROLE);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "persistent-relay:4160");

        // Should survive replacement.
        pb.replace_peer_list(&[], "mainnet", RELAY_ROLE);
        let addrs = pb.get_addresses(10, RELAY_ROLE);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "persistent-relay:4160");
    }

    #[tokio::test]
    async fn refresh_preserves_persistent_peers() {
        let pb = Arc::new(Phonebook::new(1, Duration::from_secs(1)));

        // Add a persistent peer.
        pb.add_persistent_peers(&["persistent:4160".to_string()], "mainnet", RELAY_ROLE);

        // Create discovery with some SRV results.
        let mut resolver = MockDiscoveryResolver::new();
        resolver.add_records(
            "algobootstrap",
            "mainnet.algorand.network",
            vec![SrvRecord {
                target: "dynamic-relay".to_string(),
                port: 4160,
                priority: 1,
                weight: 1,
            }],
        );
        resolver.add_records("archive", "mainnet.algorand.network", vec![]);

        let discovery = Discovery::new(
            pb.clone(),
            Box::new(resolver),
            "<network>.algorand.network",
            "mainnet",
            false,
        )
        .unwrap();

        discovery.refresh_phonebook_addresses().await;

        let mut relays = pb.get_addresses(10, RELAY_ROLE);
        relays.sort();

        // Both the persistent peer and the dynamically discovered peer should
        // be present.
        assert_eq!(relays.len(), 2);
        assert!(relays.contains(&"persistent:4160".to_string()));
        assert!(relays.contains(&"dynamic-relay:4160".to_string()));
    }
}
