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

//! `algocfg`-equivalent field get/set/reset and profile-application logic
//! (issue #973): go-algorand's `cmd/algocfg` (`getCommand.go`,
//! `setCommand.go`, `resetCommand.go`, `profileCommand.go`) reimplemented
//! against [`crate::Local`] instead of Go reflection, since Rust has no
//! runtime field reflection.
//!
//! # Mechanism, mapped to go-algorand
//!
//! | go-algorand | algod-rust |
//! |---|---|
//! | `serializeObjectProperty` (`reflect.Value.FieldByName` + `fmt.Sprintf("%v", ...)`) (`getCommand.go:70`) | [`get_property`] (`serde_json::Value` lookup by the field's `Local` JSON name, formatted the same way `fmt`'s `%v` verb would) |
//! | `setObjectProperty`/`setFieldValue` (`setCommand.go:82,94`) | [`set_property`] |
//! | `copyObjectProperty` (`resetCommand.go:79`) | [`reset_property`] |
//! | `profileNames`/`getConfigForArg` (`profileCommand.go:149,259`) | [`PROFILE_NAMES`]/[`config_for_profile`] |
//!
//! Field lookup works at the `serde_json::Value` level (Rust has no
//! `reflect.FieldByName` equivalent) rather than on the `Local` struct
//! directly: the field name a caller passes is [`Local`]'s **JSON** name
//! (its go-algorand `config.Local` field name, e.g. `"EnableP2P"`), matching
//! go's field-name resolution exactly (go's reflection also keys off the Go
//! struct field name, which is what appears in `config.json`).
//!
//! # Profile scope
//!
//! All 8 of go's named profiles (`profileNames`, `profileCommand.go:149`)
//! are ported. One field go's `wsRelay`/`archival`/`hybridRelay`/
//! `hybridArchival` profiles set — `NetAddress` — has no [`Local`]
//! equivalent: `docs/PHASE16_VALIDATION.md`'s existing scope decision (see
//! this crate's module docs, "Explicitly out of scope") keeps `NetAddress`
//! a per-subcommand CLI flag (`relay --bind-address`,
//! `participate --listen-address`) rather than a `Local` field, so those
//! four profiles simply omit that one assignment here — every other field
//! each profile sets is applied exactly as go does.

use std::collections::BTreeMap;

use crate::{ConfigError, Local};

/// Placeholder value profiles use for `PublicAddress` when the operator
/// must fill in their own externally-reachable address. Go:
/// `config.PlaceholderPublicAddress` (`config/config.go:106`).
pub const PLACEHOLDER_PUBLIC_ADDRESS: &str = "PLEASE_SET_ME";

/// Look up a [`Local`] field by its `config.json`/go field name and format
/// it the way go's `fmt.Sprintf("%v", ...)` would: a bare string (no JSON
/// quoting), a plain integer, or `true`/`false`. Go: `serializeObjectProperty`
/// (`cmd/algocfg/getCommand.go:70`).
///
/// Returns [`ConfigError::UnknownProperty`] for a name that isn't a `Local`
/// field, mirroring go's `"unknown property named '%s'"`.
pub fn get_property(cfg: &Local, name: &str) -> Result<String, ConfigError> {
    let value = field_value(cfg, name)?;
    Ok(format_go_style(&value))
}

/// Set a [`Local`] field by its `config.json`/go field name, parsing
/// `value` according to the field's existing JSON type (number, bool, or
/// string) — go: `setObjectProperty`/`setFieldValue`
/// (`cmd/algocfg/setCommand.go:82,94`). Numeric fields accept any integer
/// string (go's comment "we do not enforce bitsize" applies here too:
/// out-of-range values are rejected by `serde_json`'s own parse, not a
/// bespoke bounds check). Bool fields accept the same token set go does:
/// `t`/`true`/`True`/`TRUE`/`1` and `f`/`false`/`False`/`FALSE`/`0`.
pub fn set_property(cfg: &mut Local, name: &str, value: &str) -> Result<(), ConfigError> {
    let mut full = to_full_value(cfg)?;
    let current = field_value(cfg, name)?;
    let new_value = parse_go_style(&current, value)
        .map_err(|reason| ConfigError::InvalidPropertyValue {
            name: name.to_string(),
            value: value.to_string(),
            reason,
        })?;
    set_field(&mut full, name, new_value)?;
    *cfg = from_full_value(full)?;
    Ok(())
}

/// Reset a [`Local`] field to its default value (i.e. delete any override
/// for it) — go: `copyObjectProperty` (`cmd/algocfg/resetCommand.go:79`),
/// invoked by go's `algocfg reset` (this repo's `algod-rust algocfg
/// delete`, per issue #973's naming).
pub fn reset_property(cfg: &mut Local, name: &str) -> Result<(), ConfigError> {
    let mut full = to_full_value(cfg)?;
    let default_full = to_full_value(&Local::default())?;
    let default_value = default_full
        .get(name)
        .cloned()
        .ok_or_else(|| ConfigError::UnknownProperty {
            name: name.to_string(),
        })?;
    set_field(&mut full, name, default_value)?;
    *cfg = from_full_value(full)?;
    Ok(())
}

fn to_full_value(cfg: &Local) -> Result<serde_json::Map<String, serde_json::Value>, ConfigError> {
    match serde_json::to_value(cfg).map_err(ConfigError::Encode)? {
        serde_json::Value::Object(map) => Ok(map),
        _ => unreachable!("Local always serializes to a JSON object"),
    }
}

fn from_full_value(map: serde_json::Map<String, serde_json::Value>) -> Result<Local, ConfigError> {
    serde_json::from_value(serde_json::Value::Object(map)).map_err(ConfigError::Encode)
}

fn field_value(cfg: &Local, name: &str) -> Result<serde_json::Value, ConfigError> {
    let full = to_full_value(cfg)?;
    full.get(name)
        .cloned()
        .ok_or_else(|| ConfigError::UnknownProperty {
            name: name.to_string(),
        })
}

fn set_field(
    full: &mut serde_json::Map<String, serde_json::Value>,
    name: &str,
    value: serde_json::Value,
) -> Result<(), ConfigError> {
    if !full.contains_key(name) {
        return Err(ConfigError::UnknownProperty {
            name: name.to_string(),
        });
    }
    full.insert(name.to_string(), value);
    Ok(())
}

/// Format a `serde_json::Value` the way go's `fmt.Sprintf("%v", ...)` would
/// for the corresponding Go type: a string prints bare (no quotes), a bool
/// prints `true`/`false`, and a number prints as a plain decimal integer
/// (every numeric `Local` field is an integer type — go has no float
/// fields in `config.Local`).
fn format_go_style(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// Parse `raw` into a `serde_json::Value` matching `current`'s JSON type —
/// go's per-`reflect.Kind` switch in `setFieldValue`
/// (`cmd/algocfg/setCommand.go:94`), minus the float/uint/int distinction
/// (algod-rust's `Local` numeric fields all round-trip through
/// `serde_json::Number`, which self-selects an integer representation on
/// parse).
fn parse_go_style(current: &serde_json::Value, raw: &str) -> Result<serde_json::Value, String> {
    match current {
        serde_json::Value::String(_) => Ok(serde_json::Value::String(raw.to_string())),
        serde_json::Value::Bool(_) => match raw {
            "t" | "true" | "True" | "TRUE" | "1" => Ok(serde_json::Value::Bool(true)),
            "f" | "false" | "False" | "FALSE" | "0" => Ok(serde_json::Value::Bool(false)),
            other => Err(format!("could not parse value {other:?} as bool")),
        },
        serde_json::Value::Number(n) => {
            if n.is_u64() || n.is_i64() {
                let parsed: i128 = raw
                    .parse()
                    .map_err(|e| format!("could not parse value {raw:?} as integer: {e}"))?;
                Ok(serde_json::Value::Number(
                    serde_json::Number::from_i128(parsed)
                        .ok_or_else(|| format!("value {raw:?} out of range"))?,
                ))
            } else {
                let parsed: f64 = raw
                    .parse()
                    .map_err(|e| format!("could not parse value {raw:?} as float: {e}"))?;
                Ok(serde_json::Number::from_f64(parsed)
                    .map(serde_json::Value::Number)
                    .ok_or_else(|| format!("value {raw:?} is not a finite number"))?)
            }
        }
        other => Err(format!(
            "unsupported parameter type '{other:?}' - unable to set value"
        )),
    }
}

/// One named profile: a short description plus the [`Local`] field
/// overrides it applies on top of [`Local::default`]. Go: `configUpdater`
/// (`cmd/algocfg/profileCommand.go:34`).
pub struct Profile {
    pub description: &'static str,
    apply: fn(Local) -> Local,
}

/// go's `profileNames` map (`cmd/algocfg/profileCommand.go:149`), ported
/// 1:1 by name. See this module's doc comment for the one field
/// (`NetAddress`) some profiles omit for lack of a `Local` equivalent.
pub fn profile_names() -> BTreeMap<&'static str, Profile> {
    let mut m = BTreeMap::new();
    m.insert(
        "participation",
        Profile {
            description: "Participate in consensus or simply ensure chain health by validating blocks.",
            apply: |cfg| cfg,
        },
    );
    m.insert(
        "conduit",
        Profile {
            description: "Provide data for the Conduit tool.",
            apply: |mut cfg| {
                cfg.enable_follow_mode = true;
                cfg.max_acct_lookback = 64;
                cfg.catchup_parallel_blocks = 64;
                cfg
            },
        },
    );
    m.insert(
        "wsRelay",
        Profile {
            description: "Relay consensus messages across the ws network and support recent catchup.",
            apply: |mut cfg| {
                cfg.max_block_history_lookback = 22_000;
                cfg.catchpoint_file_history_length = 3;
                cfg.catchpoint_tracking = 2;
                cfg.enable_ledger_service = true;
                cfg.enable_block_service = true;
                cfg
            },
        },
    );
    m.insert(
        "archival",
        Profile {
            description: "Store the full chain history and support full catchup.",
            apply: |mut cfg| {
                cfg.archival = true;
                cfg.enable_ledger_service = true;
                cfg.enable_block_service = true;
                cfg.enable_gossip_service = false;
                cfg
            },
        },
    );
    m.insert(
        "development",
        Profile {
            description: "Build on Algorand.",
            apply: |mut cfg| {
                cfg.enable_experimental_api = true;
                cfg.enable_developer_api = true;
                cfg.max_acct_lookback = 256;
                cfg.enable_txn_eval_tracer = true;
                cfg.disable_api_auth = true;
                cfg
            },
        },
    );
    m.insert(
        "hybridRelay",
        Profile {
            description: "Relay consensus messages across both ws and p2p networks, also support recent catchup.",
            apply: |mut cfg| {
                cfg.max_block_history_lookback = 22_000;
                cfg.catchpoint_file_history_length = 3;
                cfg.catchpoint_tracking = 2;
                cfg.enable_ledger_service = true;
                cfg.enable_block_service = true;
                cfg.public_address = PLACEHOLDER_PUBLIC_ADDRESS.to_string();
                cfg.enable_p2p_hybrid_mode = true;
                cfg.p2p_hybrid_net_address = ":4190".to_string();
                cfg.enable_dht_providers = true;
                cfg.dht_mode = "server".to_string();
                cfg
            },
        },
    );
    m.insert(
        "hybridArchival",
        Profile {
            description: "Store the full chain history, support full catchup, P2P enabled, discoverable via DHT.",
            apply: |mut cfg| {
                cfg.archival = true;
                cfg.enable_ledger_service = true;
                cfg.enable_block_service = true;
                cfg.enable_gossip_service = false;
                cfg.public_address = PLACEHOLDER_PUBLIC_ADDRESS.to_string();
                cfg.enable_p2p_hybrid_mode = true;
                cfg.p2p_hybrid_net_address = ":4190".to_string();
                cfg.enable_dht_providers = true;
                cfg.dht_mode = "server".to_string();
                cfg
            },
        },
    );
    m.insert(
        "hybridClient",
        Profile {
            description: "Participate in consensus or simply ensure chain health by validating blocks and supporting P2P traffic propagation.",
            apply: |mut cfg| {
                cfg.enable_p2p_hybrid_mode = true;
                cfg.enable_dht_providers = true;
                cfg.dht_mode = "client".to_string();
                cfg
            },
        },
    );
    m
}

/// Resolve a profile name to its fully-materialized [`Local`] config — go:
/// `getConfigForArg` (`cmd/algocfg/profileCommand.go:259`). Returns
/// [`ConfigError::UnknownProfile`] naming every valid profile, matching
/// go's error message shape.
pub fn config_for_profile(name: &str) -> Result<Local, ConfigError> {
    let profiles = profile_names();
    match profiles.get(name) {
        Some(profile) => Ok((profile.apply)(Local::default())),
        None => {
            let mut names: Vec<&str> = profiles.keys().copied().collect();
            names.sort_unstable();
            Err(ConfigError::UnknownProfile {
                name: name.to_string(),
                valid: names.join(", "),
            })
        }
    }
}

/// Shell-quote a value for safe use as a POSIX shell word — algod-rust's
/// `algocfg string` subcommand (issue #973's "print as a shell-quoted
/// string" addition; go-algorand's `algocfg get` never quotes its output).
/// Always single-quotes, escaping any embedded single quote as the
/// standard `'"'"'` POSIX idiom, so the result is safe to paste into a
/// shell command (e.g. `algod-rust algocfg set -p DNSBootstrapID -v
/// "$(algod-rust algocfg string -p DNSBootstrapID -d other-datadir)"`).
pub fn shell_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\"'\"'");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_property_formats_string_bool_and_integer_fields() {
        let cfg = Local::default();
        assert_eq!(
            get_property(&cfg, "DNSBootstrapID").unwrap(),
            cfg.dns_bootstrap_id
        );
        assert_eq!(
            get_property(&cfg, "EnableP2P").unwrap(),
            cfg.enable_p2p.to_string()
        );
        assert_eq!(
            get_property(&cfg, "GossipFanout").unwrap(),
            cfg.gossip_fanout.to_string()
        );
    }

    #[test]
    fn get_property_unknown_field_errors() {
        let cfg = Local::default();
        let err = get_property(&cfg, "NotARealField").unwrap_err();
        assert!(matches!(err, ConfigError::UnknownProperty { .. }));
        assert!(err.to_string().contains("NotARealField"));
    }

    #[test]
    fn set_property_round_trips_bool_field() {
        let mut cfg = Local::default();
        assert!(!cfg.enable_p2p);
        set_property(&mut cfg, "EnableP2P", "true").unwrap();
        assert!(cfg.enable_p2p);
        set_property(&mut cfg, "EnableP2P", "0").unwrap();
        assert!(!cfg.enable_p2p);
    }

    #[test]
    fn set_property_round_trips_integer_field() {
        let mut cfg = Local::default();
        set_property(&mut cfg, "GossipFanout", "9").unwrap();
        assert_eq!(cfg.gossip_fanout, 9);
    }

    #[test]
    fn set_property_round_trips_string_field() {
        let mut cfg = Local::default();
        set_property(&mut cfg, "TLSCertFile", "/etc/algod/cert.pem").unwrap();
        assert_eq!(cfg.tls_cert_file, "/etc/algod/cert.pem");
    }

    #[test]
    fn set_property_rejects_invalid_bool() {
        let mut cfg = Local::default();
        let err = set_property(&mut cfg, "EnableP2P", "maybe").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPropertyValue { .. }));
    }

    #[test]
    fn set_property_rejects_invalid_integer() {
        let mut cfg = Local::default();
        let err = set_property(&mut cfg, "GossipFanout", "not-a-number").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPropertyValue { .. }));
    }

    #[test]
    fn set_property_unknown_field_errors() {
        let mut cfg = Local::default();
        let err = set_property(&mut cfg, "NotARealField", "1").unwrap_err();
        assert!(matches!(err, ConfigError::UnknownProperty { .. }));
    }

    #[test]
    fn reset_property_restores_default_after_override() {
        let mut cfg = Local::default();
        let default_fanout = cfg.gossip_fanout;
        set_property(&mut cfg, "GossipFanout", "99").unwrap();
        assert_eq!(cfg.gossip_fanout, 99);
        reset_property(&mut cfg, "GossipFanout").unwrap();
        assert_eq!(cfg.gossip_fanout, default_fanout);
    }

    #[test]
    fn reset_property_unknown_field_errors() {
        let mut cfg = Local::default();
        let err = reset_property(&mut cfg, "NotARealField").unwrap_err();
        assert!(matches!(err, ConfigError::UnknownProperty { .. }));
    }

    // --- Profile tests, pinned to go's profileCommand_test.go -------------

    #[test]
    fn unknown_profile_error_lists_every_valid_name() {
        let err = config_for_profile("invalid").unwrap_err();
        let ConfigError::UnknownProfile { valid, .. } = &err else {
            panic!("expected UnknownProfile, got {err:?}");
        };
        for name in profile_names().keys() {
            assert!(
                valid.contains(name),
                "expected {valid:?} to contain {name:?}"
            );
        }
    }

    #[test]
    fn conduit_profile_matches_go() {
        let cfg = config_for_profile("conduit").unwrap();
        assert!(cfg.enable_follow_mode);
        assert_eq!(cfg.max_acct_lookback, 64);
        assert_eq!(cfg.catchup_parallel_blocks, 64);
    }

    #[test]
    fn development_profile_matches_go() {
        let cfg = config_for_profile("development").unwrap();
        assert!(cfg.disable_api_auth);
        assert!(cfg.enable_experimental_api);
        assert!(cfg.enable_developer_api);
        assert_eq!(cfg.max_acct_lookback, 256);
        assert!(cfg.enable_txn_eval_tracer);
    }

    #[test]
    fn archival_profile_matches_go() {
        let cfg = config_for_profile("archival").unwrap();
        assert!(cfg.archival);
        assert!(cfg.enable_ledger_service);
        assert!(cfg.enable_block_service);
        assert!(!cfg.enable_gossip_service);
    }

    #[test]
    fn hybrid_relay_profile_matches_go() {
        let cfg = config_for_profile("hybridRelay").unwrap();
        assert!(!cfg.archival);
        assert_eq!(cfg.max_block_history_lookback, 22_000);
        assert_eq!(cfg.catchpoint_file_history_length, 3);
        assert_eq!(cfg.catchpoint_tracking, 2);
        assert!(cfg.enable_ledger_service);
        assert!(cfg.enable_block_service);
        assert!(cfg.enable_gossip_service);
        assert_eq!(cfg.public_address, PLACEHOLDER_PUBLIC_ADDRESS);
        assert!(cfg.enable_p2p_hybrid_mode);
        assert_eq!(cfg.p2p_hybrid_net_address, ":4190");
        assert!(cfg.enable_dht_providers);
        assert_eq!(cfg.dht_mode, "server");
    }

    #[test]
    fn hybrid_archival_profile_matches_go() {
        let cfg = config_for_profile("hybridArchival").unwrap();
        assert!(cfg.archival);
        assert_eq!(cfg.max_block_history_lookback, 0);
        assert_eq!(cfg.catchpoint_file_history_length, 365);
        assert_eq!(cfg.catchpoint_tracking, 0);
        assert!(cfg.enable_ledger_service);
        assert!(cfg.enable_block_service);
        assert!(!cfg.enable_gossip_service);
        assert_eq!(cfg.public_address, PLACEHOLDER_PUBLIC_ADDRESS);
        assert!(cfg.enable_p2p_hybrid_mode);
        assert_eq!(cfg.p2p_hybrid_net_address, ":4190");
        assert!(cfg.enable_dht_providers);
        assert_eq!(cfg.dht_mode, "server");
    }

    #[test]
    fn hybrid_client_profile_matches_go() {
        let cfg = config_for_profile("hybridClient").unwrap();
        assert!(!cfg.archival);
        assert_eq!(cfg.max_block_history_lookback, 0);
        assert!(!cfg.enable_ledger_service);
        assert!(!cfg.enable_block_service);
        assert!(cfg.enable_gossip_service);
        assert_eq!(cfg.public_address, "");
        assert!(cfg.enable_p2p_hybrid_mode);
        assert_eq!(cfg.p2p_hybrid_net_address, "");
        assert!(cfg.enable_dht_providers);
        assert_eq!(cfg.dht_mode, "client");
    }

    #[test]
    fn participation_profile_is_identity() {
        assert_eq!(config_for_profile("participation").unwrap(), Local::default());
    }

    #[test]
    fn shell_quote_wraps_plain_value() {
        assert_eq!(shell_quote("hello"), "'hello'");
    }

    #[test]
    fn shell_quote_escapes_embedded_single_quote() {
        assert_eq!(shell_quote("it's"), "'it'\"'\"'s'");
    }
}
