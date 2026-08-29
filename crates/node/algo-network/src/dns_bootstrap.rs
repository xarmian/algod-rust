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

//! DNS bootstrap ID parsing for peer discovery.
//!
//! Matches the behaviour of go-algorand's `config/dnsbootstrap.go`:
//! parses a template string such as
//!
//! ```text
//! <network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)
//! ```
//!
//! into a [`DnsBootstrap`] containing the primary SRV domain, an optional
//! backup SRV domain, and an optional deduplication regex.

use std::sync::OnceLock;

use regex::Regex;
use thiserror::Error;
use url::Url;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced while parsing a DNS bootstrap ID string.
#[derive(Debug, Error)]
pub enum DnsBootstrapError {
    /// The bootstrap ID was empty (or whitespace-only) after template
    /// substitution and trimming.
    #[error("DNSBootstrapID must be non-empty and a valid URL")]
    Empty,

    /// The bootstrap ID could not be parsed as a URL.
    #[error("invalid formatted DNSBootstrapID: {0}")]
    InvalidFormat(String),

    /// The URL query string could not be parsed.
    #[error("error parsing query params from DNSBootstrapID: {0}")]
    InvalidQueryParams(String),

    /// The `<name>` macro appears somewhere other than the start of the dedup
    /// expression.
    #[error("invalid usage of <name> macro in dedup param; must be at the beginning of the expression: {0}")]
    InvalidNameMacro(String),

    /// The dedup expression (after `<name>` removal) is not a valid regex.
    #[error("dedup regex does not compile: {0}")]
    DedupRegexInvalid(String),
}

// ---------------------------------------------------------------------------
// DnsBootstrap
// ---------------------------------------------------------------------------

/// Parsed DNS bootstrap entry for SRV-based peer discovery.
#[derive(Debug, Clone)]
pub struct DnsBootstrap {
    /// Primary SRV bootstrap domain (e.g. `mainnet.algorand.network`).
    pub primary_srv_bootstrap: String,

    /// Optional backup SRV bootstrap domain (e.g. `mainnet.algorand.net`).
    pub backup_srv_bootstrap: String,

    /// Optional regex used to deduplicate SRV records returned from the
    /// primary and backup DNS servers.
    pub dedup_exp: Option<Regex>,
}

// ---------------------------------------------------------------------------
// Network override map
// ---------------------------------------------------------------------------

/// For devnet/betanet/alphanet the bootstrap is hardcoded to `*.algodev.network`
/// unless the caller has explicitly overridden the default template.
fn network_bootstrap_override(network: &str) -> Option<DnsBootstrap> {
    match network {
        "devnet" => Some(DnsBootstrap {
            primary_srv_bootstrap: "devnet.algodev.network".to_string(),
            backup_srv_bootstrap: String::new(),
            dedup_exp: None,
        }),
        "betanet" => Some(DnsBootstrap {
            primary_srv_bootstrap: "betanet.algodev.network".to_string(),
            backup_srv_bootstrap: String::new(),
            dedup_exp: None,
        }),
        "alphanet" => Some(DnsBootstrap {
            primary_srv_bootstrap: "alphanet.algodev.network".to_string(),
            backup_srv_bootstrap: String::new(),
            dedup_exp: None,
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Regex for the `<name>` macro
// ---------------------------------------------------------------------------

/// Returns the compiled `<name>` macro regex, initialised once on first
/// access.  Matches the `<name>` macro with an optional trailing dot,
/// exactly like Go's `regexp.MustCompile(`<name>\.?`)`.
fn name_exp() -> &'static Regex {
    static NAME_EXP: OnceLock<Regex> = OnceLock::new();
    NAME_EXP.get_or_init(|| Regex::new(r"<name>\.?").expect("<name> regex must compile"))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a single DNS bootstrap ID string into a [`DnsBootstrap`].
///
/// `dns_bootstrap_id` is a template string that may contain `<network>` and
/// `<name>` macros.  `network` is substituted for `<network>`.
///
/// When `default_template_overridden` is `false`, devnet / betanet / alphanet
/// networks are short-circuited to their hardcoded override entries.
pub fn parse_dns_bootstrap(
    dns_bootstrap_id: &str,
    network: &str,
    default_template_overridden: bool,
) -> Result<DnsBootstrap, DnsBootstrapError> {
    // 1. For non-overridden templates, check the hardcoded override map.
    if !default_template_overridden {
        if let Some(bootstrap) = network_bootstrap_override(network) {
            return Ok(bootstrap);
        }
    }

    // 2. Normalize: lowercase, trim, substitute <network>.
    let id = dns_bootstrap_id
        .to_lowercase()
        .trim()
        .to_string()
        .replace("<network>", network);

    if id.is_empty() {
        return Err(DnsBootstrapError::Empty);
    }

    // 3. Parse as URL. If the host is empty, try again with "https://" prefix.
    let parsed = match Url::parse(&id) {
        Ok(u) if !u.host_str().unwrap_or("").is_empty() => u,
        Ok(_) | Err(_) => {
            let with_scheme = format!("https://{}", id);
            Url::parse(&with_scheme)
                .map_err(|e| DnsBootstrapError::InvalidFormat(format!("{}, error: {}", id, e)))?
        }
    };

    // 4. Extract host.
    let host = parsed.host_str().unwrap_or("").to_string();
    if host.is_empty() {
        return Err(DnsBootstrapError::InvalidFormat(id));
    }

    // 5. Parse query params.
    // Use url::form_urlencoded instead of Url::query_pairs so we match Go's
    // url.ParseQuery behaviour (which errors on malformed percent-encoding).
    // Url::query_pairs() silently replaces invalid sequences, so we manually
    // validate the raw query first.
    let raw_query = parsed.query().unwrap_or("");
    let query_pairs: Vec<(String, String)> = if raw_query.is_empty() {
        Vec::new()
    } else {
        // Manually check for invalid percent-encoding that Go would reject.
        validate_query_encoding(raw_query, &id)?;
        url::form_urlencoded::parse(raw_query.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };

    // 6. Extract backup param.
    let backup_srv_bootstrap = query_pairs
        .iter()
        .find(|(k, _)| k == "backup")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    // 7. Build optional dedup regex (only considered when backup is non-empty).
    let dedup_exp = if !backup_srv_bootstrap.is_empty() {
        build_dedup_regex(&query_pairs, &id)?
    } else {
        None
    };

    Ok(DnsBootstrap {
        primary_srv_bootstrap: host,
        backup_srv_bootstrap,
        dedup_exp,
    })
}

/// Parse a semicolon-separated list of DNS bootstrap ID entries.
///
/// Empty entries (whitespace-only segments between semicolons) are silently
/// skipped.  Parsing stops on the first error.
pub fn parse_dns_bootstrap_array(
    dns_bootstrap_id: &str,
    network: &str,
    default_template_overridden: bool,
) -> Result<Vec<DnsBootstrap>, DnsBootstrapError> {
    let mut result = Vec::new();
    for entry in dns_bootstrap_id.split(';') {
        if entry.trim().is_empty() {
            continue;
        }
        let bootstrap = parse_dns_bootstrap(entry, network, default_template_overridden)?;
        result.push(bootstrap);
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate that percent-encoding in the query string is well-formed.
///
/// Go's `url.ParseQuery` rejects strings like `%%b`, while Rust's
/// `form_urlencoded::parse` silently replaces them.  We replicate Go's
/// behaviour so the same inputs produce errors.
fn validate_query_encoding(raw_query: &str, id: &str) -> Result<(), DnsBootstrapError> {
    let bytes = raw_query.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if bytes[i] == b'%' {
            // Need at least two hex digits following.
            if i + 2 >= len
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return Err(DnsBootstrapError::InvalidQueryParams(id.to_string()));
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    Ok(())
}

/// Build an optional dedup [`Regex`] from the query parameters.
///
/// The `<name>` macro, if present, must appear only at the start of the dedup
/// expression (with an optional trailing dot).  After stripping `<name>`, the
/// remaining string is wrapped in parentheses and compiled as a regex.
fn build_dedup_regex(
    query_pairs: &[(String, String)],
    id: &str,
) -> Result<Option<Regex>, DnsBootstrapError> {
    let dedup_param = query_pairs
        .iter()
        .find(|(k, _)| k == "dedup")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    if dedup_param.is_empty() {
        return Ok(None);
    }

    let name_re = name_exp();

    // Validate that <name> only appears at position 0.
    for m in name_re.find_iter(dedup_param) {
        if m.start() != 0 {
            return Err(DnsBootstrapError::InvalidNameMacro(id.to_string()));
        }
    }

    // Strip the leading <name> (with optional dot) from the dedup expression.
    let stripped = name_re.replace_all(dedup_param, "").to_string();

    // Wrap in parens and compile.
    let pattern = format!("({})", stripped);
    let re = Regex::new(&pattern)
        .map_err(|e| DnsBootstrapError::DedupRegexInvalid(format!("{}, error: {}", id, e)))?;

    Ok(Some(re))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Default template with various networks --

    /// Mirrors Go's `TestParseDNSBootstrapIDBackupWithExpectedDefaultTemplate`.
    #[test]
    fn parse_default_template_mainnet() {
        let template = "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)";
        let network = "mainnet";

        let b = parse_dns_bootstrap(template, network, true).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "mainnet.algorand.network");
        assert_eq!(b.backup_srv_bootstrap, "mainnet.algorand.net");
        assert_eq!(
            b.dedup_exp.as_ref().unwrap().as_str(),
            "(algorand-mainnet.(network|net))"
        );
    }

    #[test]
    fn parse_default_template_testnet() {
        let template = "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)";
        let network = "testnet";

        let b = parse_dns_bootstrap(template, network, true).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "testnet.algorand.network");
        assert_eq!(b.backup_srv_bootstrap, "testnet.algorand.net");
        assert_eq!(
            b.dedup_exp.as_ref().unwrap().as_str(),
            "(algorand-testnet.(network|net))"
        );
    }

    // -- Hardcoded network overrides (default_template_overridden = false) --

    /// Mirrors Go's `TestParseDNSBootstrapIDBackupWithHardCodedNetworkBootstraps`.
    #[test]
    fn hardcoded_devnet_override() {
        let template = "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)";
        let b = parse_dns_bootstrap(template, "devnet", false).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "devnet.algodev.network");
        assert_eq!(b.backup_srv_bootstrap, "");
        assert!(b.dedup_exp.is_none());
    }

    #[test]
    fn hardcoded_betanet_override() {
        let template = "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)";
        let b = parse_dns_bootstrap(template, "betanet", false).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "betanet.algodev.network");
        assert_eq!(b.backup_srv_bootstrap, "");
        assert!(b.dedup_exp.is_none());
    }

    #[test]
    fn hardcoded_alphanet_override() {
        let template = "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)";
        let b = parse_dns_bootstrap(template, "alphanet", false).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "alphanet.algodev.network");
        assert_eq!(b.backup_srv_bootstrap, "");
        assert!(b.dedup_exp.is_none());
    }

    /// When default_template_overridden = true, even devnet goes through normal parsing.
    #[test]
    fn devnet_override_bypassed_when_overridden() {
        let template = "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)";
        let b = parse_dns_bootstrap(template, "devnet", true).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "devnet.algorand.network");
        assert_eq!(b.backup_srv_bootstrap, "devnet.algorand.net");
        assert!(b.dedup_exp.is_some());
    }

    // -- Legacy template (no backup, no dedup) --

    /// Mirrors Go's `TestParseDNSBootstrapIDWithLegacyTemplate`.
    #[test]
    fn legacy_template_no_backup() {
        let template = "<network>.algorand.network";
        let b = parse_dns_bootstrap(template, "mainnet", true).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "mainnet.algorand.network");
        assert_eq!(b.backup_srv_bootstrap, "");
        assert!(b.dedup_exp.is_none());
    }

    #[test]
    fn legacy_template_testnet() {
        let template = "<network>.algorand.network";
        let b = parse_dns_bootstrap(template, "testnet", true).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "testnet.algorand.network");
        assert!(b.dedup_exp.is_none());
    }

    // -- No backup (dedup is ignored without backup) --

    /// Mirrors Go's `TestParseDNSBootstrapIDNoBackup`.
    #[test]
    fn no_backup_dedup_ignored() {
        let template = "example.com?dedup=<name>.algorand-<network>.(net|network)";
        let b = parse_dns_bootstrap(template, "mainnet", true).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "example.com");
        assert_eq!(b.backup_srv_bootstrap, "");
        assert!(b.dedup_exp.is_none());
    }

    #[test]
    fn no_backup_with_https_prefix() {
        let template = "https://example.com?dedup=<name>.algorand-<network>.(net|network)";
        let b = parse_dns_bootstrap(template, "mainnet", true).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "example.com");
        assert_eq!(b.backup_srv_bootstrap, "");
        assert!(b.dedup_exp.is_none());
    }

    // -- Backup without dedup --

    /// Mirrors Go's `TestParseDNSBootstrapIDBackupNoDedup`.
    #[test]
    fn backup_no_dedup() {
        let b =
            parse_dns_bootstrap("example.com?backup=backup.example.com", "mainnet", true).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "example.com");
        assert_eq!(b.backup_srv_bootstrap, "backup.example.com");
        assert!(b.dedup_exp.is_none());
    }

    // -- Backup with single-domain dedup --

    /// Mirrors Go's `TestParseDNSBootstrapIDBackupWithSingleDomainDedup`.
    #[test]
    fn backup_with_single_domain_dedup() {
        let template =
            "example.com?backup=backup.example.com&dedup=<name>.algorand-<network>.network";
        let b = parse_dns_bootstrap(template, "mainnet", true).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "example.com");
        assert_eq!(b.backup_srv_bootstrap, "backup.example.com");
        assert_eq!(
            b.dedup_exp.as_ref().unwrap().as_str(),
            "(algorand-mainnet.network)"
        );
    }

    // -- Empty / whitespace inputs --

    /// Mirrors Go's `TestParseDNSBootstrapIDEmptySpaceURLsRejected`.
    #[test]
    fn empty_bootstrap_id_rejected() {
        let err = parse_dns_bootstrap("", "mainnet", false).unwrap_err();
        assert!(
            matches!(err, DnsBootstrapError::Empty),
            "expected Empty, got: {err}"
        );
    }

    #[test]
    fn whitespace_only_rejected() {
        let err = parse_dns_bootstrap("  ", "testnet", false).unwrap_err();
        assert!(
            matches!(err, DnsBootstrapError::Empty),
            "expected Empty, got: {err}"
        );
    }

    // -- Invalid URLs --

    /// Mirrors Go's `TestParseDNSBootstrapIDInvalidURLsRejected`.
    #[test]
    fn invalid_url_rejected() {
        let err = parse_dns_bootstrap(
            "algo@%%@api^^.google.com/q?backup=api.google.net",
            "mainnet",
            false,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                DnsBootstrapError::InvalidFormat(_) | DnsBootstrapError::InvalidQueryParams(_)
            ),
            "expected InvalidFormat or InvalidQueryParams, got: {err}"
        );
    }

    // -- Invalid query params --

    /// Mirrors Go's `TestParseDNSBootstrapIDInvalidQueryParamsRejected`.
    #[test]
    fn invalid_query_params_rejected() {
        let err = parse_dns_bootstrap(
            "http://api.google.com/q?backup=api.google.net&dedup=%%b",
            "mainnet",
            false,
        )
        .unwrap_err();
        assert!(
            matches!(err, DnsBootstrapError::InvalidQueryParams(_)),
            "expected InvalidQueryParams, got: {err}"
        );
    }

    // -- Invalid <name> macro position --

    /// Mirrors Go's `TestParseDNSBootstrapIDInvalidNameMacroPosition`.
    #[test]
    fn invalid_name_macro_position() {
        let template = "<network>.algorand.network?backup=<network>.algorand.net&dedup=algorand-<name>.algorand-<network>.(network|net)";
        let err = parse_dns_bootstrap(template, "mainnet", false).unwrap_err();
        assert!(
            matches!(err, DnsBootstrapError::InvalidNameMacro(_)),
            "expected InvalidNameMacro, got: {err}"
        );
    }

    // -- Invalid dedup regex --

    /// Mirrors Go's `TestParseDNSBootstrapIDInvalidDedupRegex`.
    #[test]
    fn invalid_dedup_regex() {
        let template = "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.((network|net)";
        let err = parse_dns_bootstrap(template, "mainnet", false).unwrap_err();
        assert!(
            matches!(err, DnsBootstrapError::DedupRegexInvalid(_)),
            "expected DedupRegexInvalid, got: {err}"
        );
    }

    // -- Semicolon-separated array parsing --

    #[test]
    fn parse_array_single_entry() {
        let entries =
            parse_dns_bootstrap_array("<network>.algorand.network", "mainnet", true).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].primary_srv_bootstrap, "mainnet.algorand.network");
    }

    #[test]
    fn parse_array_multiple_entries() {
        let template = "<network>.algorand.network;<network>.algorand.net";
        let entries = parse_dns_bootstrap_array(template, "mainnet", true).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].primary_srv_bootstrap, "mainnet.algorand.network");
        assert_eq!(entries[1].primary_srv_bootstrap, "mainnet.algorand.net");
    }

    #[test]
    fn parse_array_skips_empty_segments() {
        let template = "<network>.algorand.network;;  ; <network>.algorand.net";
        let entries = parse_dns_bootstrap_array(template, "mainnet", true).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn parse_array_stops_on_first_error() {
        let template = "<network>.algorand.network;  ";
        let entries = parse_dns_bootstrap_array(template, "mainnet", true).unwrap();
        // The second segment is whitespace-only and is skipped.
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn parse_array_error_propagates() {
        // Second entry has an invalid dedup regex.
        let template = "<network>.algorand.network;<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.((network|net)";
        let err = parse_dns_bootstrap_array(template, "mainnet", true).unwrap_err();
        assert!(
            matches!(err, DnsBootstrapError::DedupRegexInvalid(_)),
            "expected DedupRegexInvalid, got: {err}"
        );
    }

    // -- Network substitution --

    #[test]
    fn network_substituted_in_all_fields() {
        let template = "<network>.example.com?backup=<network>.backup.com&dedup=<name>.<network>-dedup.(com|net)";
        let b = parse_dns_bootstrap(template, "testnet", true).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "testnet.example.com");
        assert_eq!(b.backup_srv_bootstrap, "testnet.backup.com");
        assert_eq!(
            b.dedup_exp.as_ref().unwrap().as_str(),
            "(testnet-dedup.(com|net))"
        );
    }

    // -- Case insensitivity --

    #[test]
    fn input_is_lowercased() {
        let template = "<NETWORK>.ALGORAND.NETWORK";
        let b = parse_dns_bootstrap(template, "mainnet", true).unwrap();
        assert_eq!(b.primary_srv_bootstrap, "mainnet.algorand.network");
    }

    // -- Dedup with <name> at start (with dot) --

    #[test]
    fn name_with_dot_stripped() {
        let template = "p.com?backup=b.com&dedup=<name>.algorand.network";
        let b = parse_dns_bootstrap(template, "mainnet", true).unwrap();
        assert_eq!(b.dedup_exp.as_ref().unwrap().as_str(), "(algorand.network)");
    }

    // -- Dedup without <name> --

    #[test]
    fn dedup_without_name_macro() {
        let template = "p.com?backup=b.com&dedup=algorand.(net|network)";
        let b = parse_dns_bootstrap(template, "mainnet", true).unwrap();
        assert_eq!(
            b.dedup_exp.as_ref().unwrap().as_str(),
            "(algorand.(net|network))"
        );
    }

    // -- Override map entries --

    #[test]
    fn override_map_has_correct_entries() {
        assert!(network_bootstrap_override("devnet").is_some());
        assert!(network_bootstrap_override("betanet").is_some());
        assert!(network_bootstrap_override("alphanet").is_some());
        assert!(network_bootstrap_override("mainnet").is_none());
        assert!(network_bootstrap_override("testnet").is_none());
    }

    // -- name_exp regex --

    #[test]
    fn name_exp_matches_with_and_without_dot() {
        let re = name_exp();
        assert!(re.is_match("<name>"));
        assert!(re.is_match("<name>."));
        assert!(!re.is_match("name"));
        assert!(!re.is_match("<Name>"));
    }

    // -- Error display messages --

    #[test]
    fn error_display_empty() {
        let err = DnsBootstrapError::Empty;
        assert_eq!(
            err.to_string(),
            "DNSBootstrapID must be non-empty and a valid URL"
        );
    }

    #[test]
    fn error_display_invalid_name_macro() {
        let err = DnsBootstrapError::InvalidNameMacro("test".to_string());
        assert!(err.to_string().contains("invalid usage of <name> macro"));
    }

    #[test]
    fn error_display_dedup_regex_invalid() {
        let err = DnsBootstrapError::DedupRegexInvalid("test".to_string());
        assert!(err.to_string().contains("dedup regex does not compile"));
    }
}
