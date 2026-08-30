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

//! `config.json` loading + version migration — go-algorand's `config.Local`
//! equivalent (issue #754, part of epic #745 / Phase 16).
//!
//! This crate is the **foundational plumbing only**: a small,
//! genuinely-extensible mechanism that mirrors go-algorand's exact
//! partial-overlay + version-migration semantics
//! (`../go-algorand/config/{localTemplate,config,migrate}.go`), seeded with
//! a handful of proof-of-concept fields. Per-area field gaps (networking,
//! storage, REST/API, catchup, agreement, telemetry) are separate
//! follow-up issues under epic #745 that add many more fields to
//! [`Local`] using the same mechanism — see "Adding a new field" below.
//!
//! # The mechanism, mapped to go-algorand
//!
//! | go-algorand | algod-rust |
//! |---|---|
//! | `Local` struct + `version[N]:"default"` struct tags (`localTemplate.go`) | [`Local`] struct + a [`VersionedDefault`] static per field |
//! | `defaultLocal` (generated, fully materialized at the latest version) | `Local::default()` (calls [`Local::default_at_version`]`(`[`LATEST_VERSION`]`)`) |
//! | `loadConfigFromFile`: `c = defaultLocal; c.Version = 0; json.Decode` (partial overlay for free) | [`serde`] `#[serde(default = "...")]` **per field** — every field falls back to its own latest-version default when absent from the JSON, while `version` falls back to `0` (its `u32::default()`), exactly mirroring go's explicit "reset to 0 so we get the version from the loaded file" |
//! | `migrate(cfg Local)` (`migrate.go:39`) | [`Local::migrate`] |
//! | `GetVersionedDefaultLocalConfig(version)` (`migrate.go:181`) | [`VersionedDefault::at`] |
//! | `SaveNonDefaultValuesToFile` (`localTemplate.go:722`) | [`Local::to_json_minimized`] / [`Local::save_non_default_to_path`] |
//! | `config.json` / `ConfigFilename` | [`CONFIG_FILENAME`] |
//!
//! # Adding a new field (for the per-area follow-up issues)
//!
//! 1. Add the field to the [`Local`] struct with `#[serde(rename = "GoFieldName", default = "default_my_field")]`
//!    (use the exact go field name for `rename` when porting a real
//!    `config.Local` field, so an operator's real `config.json` round-trips
//!    byte-for-byte for that field).
//! 2. Add a `static MY_FIELD: VersionedDefault<T> = VersionedDefault::new(&[...]);`
//!    with one `(version, || default)` entry per `version[N]:"default"` tag
//!    the field carries in `../go-algorand/config/localTemplate.go` (or, for
//!    an algod-rust-only field with no go equivalent, a single `(0, || default)`
//!    entry). `T` only needs `Default` (+ `PartialEq` for migration) — it does
//!    **not** need to be `Copy`, so `String`/`Vec`/map-typed fields work too.
//! 3. Add `field: MY_FIELD.at(version),` to [`Local::default_at_version`].
//! 4. Add `fn default_my_field() -> T { MY_FIELD.at(LATEST_VERSION) }` and
//!    reference it from the field's `#[serde(default = "...")]`.
//! 5. Add `migrate_field(&mut self.my_field, &MY_FIELD, cur, next);` to
//!    [`Local::migrate`]'s per-step block.
//! 6. If the field's highest tag exceeds the current [`LATEST_VERSION`],
//!    bump the constant — `latest_version_matches_max_field_tag` (in this
//!    crate's tests) enforces they stay in sync.
//!
//! # Explicitly out of scope for this issue
//!
//! - The remaining `config.Local` fields with no underlying algod-rust
//!   feature to gate yet (message-hash-bucket dedup filtering, DHT peer
//!   discovery, vote compression, ed25519 batch verification, per-IP
//!   priority peers, reserved-FD accounting, X-Forwarded-For handling,
//!   request logging, DNS security flags) — tracked by epic #745's
//!   networking follow-up rather than added here as no-op knobs (see
//!   PR description for #748 for the full enumerated list with go
//!   defaults and disposition).
//! - `enrichNetworkingConfig`'s field-level post-load normalization
//!   (`NetAddress`-driven `GossipFanout`/`EnableLedgerService` side effects,
//!   `PublicAddress` lowercasing) — that's networking-config-field-gap
//!   territory (#748, tracked further in its follow-up). The mechanism here
//!   is structured so such a hook can be layered on after
//!   [`Local::load_from_data_dir`] without any architectural change.
//! - Wiring every field into actual runtime behavior — left to the owning
//!   per-area issue, since each one needs to decide the exact
//!   CLI-flag/TOML/`config.json` precedence for its own fields. #748 wires
//!   `max_connections_per_ip`, `incoming_connections_limit`,
//!   `broadcast_connections_limit`, `connections_rate_limiting_count`/
//!   `_window_seconds`, `tls_cert_file`/`tls_key_file`,
//!   `enable_gossip_service`/`enable_block_service`/
//!   `enable_gossip_block_service`, `disable_api_auth`, and
//!   `block_service_mem_cap` into `algo-network`/`algo-rest-api` — see that
//!   issue's PR description for exactly which code path each one drives.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Filename go-algorand (and algod-rust) reads relative to the node's data
/// directory. Go: `config.ConfigFilename` (`config/config.go:61`).
pub const CONFIG_FILENAME: &str = "config.json";

/// Highest version any field on [`Local`] carries a tag for. Every field's
/// version history in this file must top out at or below this value; the
/// `latest_version_matches_max_field_tag` test enforces that they stay in
/// sync, mirroring go's `!!! WARNING !!!` comment on `Local.Version`
/// ("This field tag must be updated any time we add a new version").
pub const LATEST_VERSION: u32 = 35;

/// Errors from loading, migrating, or saving a [`Local`] config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file exists but could not be read (permissions, I/O failure,
    /// etc.) — NOT raised for a merely-absent file, which is treated as
    /// "use defaults" (see [`Local::load_from_data_dir`]).
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The file's JSON could not be parsed into [`Local`].
    #[error("failed to parse {path} as {CONFIG_FILENAME}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// The loaded config's `version` is newer than this binary knows about.
    /// Mirrors go's guard in `migrate()` (`migrate.go:44`:
    /// `if cfg.Version > latestConfigVersion { err = ... }`) — an untrusted
    /// or hand-edited `config.json` claiming a future version must be
    /// rejected with an error rather than silently misbehaving or panicking.
    #[error(
        "config.json version {found} is newer than this binary supports (latest known version is {latest})"
    )]
    VersionTooNew { found: u32, latest: u32 },

    /// Serializing a [`Local`] back to JSON failed (should not happen for
    /// this struct's field types; kept for forward-compatibility as fields
    /// are added).
    #[error("failed to encode config as JSON: {0}")]
    Encode(#[source] serde_json::Error),
}

/// One field's version-tagged default-value history, mirroring go's
/// `version[N]:"default"` struct-tag convention
/// (`../go-algorand/config/localTemplate.go`). Entries MUST be sorted
/// ascending by version and MUST include an entry at version 0 (mirrors
/// every field in go's generated `defaultLocal` having a value from version
/// 0 onward).
/// One `(version, default-value constructor)` entry in a
/// [`VersionedDefault`]'s history. A type alias keeps the entries slice
/// type from tripping clippy's `type_complexity` lint.
pub type VersionedDefaultEntry<T> = (u32, fn() -> T);

pub struct VersionedDefault<T: 'static> {
    /// `(version, default-value constructor)` pairs, ascending by version.
    entries: &'static [VersionedDefaultEntry<T>],
}

impl<T: Default> VersionedDefault<T> {
    /// Build a version history from its `(version, default)` entries.
    pub const fn new(entries: &'static [VersionedDefaultEntry<T>]) -> Self {
        Self { entries }
    }

    /// What this field's default value would be at `version`, replaying
    /// version tags in ascending order — go's
    /// `GetVersionedDefaultLocalConfig` (`config/migrate.go:181`). Before
    /// this field's first tag applies, the value is `T::default()` —
    /// Rust's zero value, matching go's untagged zero value (e.g. `0` for
    /// `int`, `false` for `bool`, `""` for `string`).
    ///
    /// `T` only needs [`Default`] here (not `Copy`) — each matching entry's
    /// constructor is called fresh, never duplicated from a prior value.
    pub fn at(&self, version: u32) -> T {
        let mut chosen: T = T::default();
        for (v, f) in self.entries {
            if *v <= version {
                chosen = f();
            } else {
                break;
            }
        }
        chosen
    }

    /// Whether this field carries an explicit `version[version]` tag —
    /// go's `reflect.StructTag(...).Lookup("version[N]")`'s `hasTag`.
    pub fn has_tag(&self, version: u32) -> bool {
        self.entries.iter().any(|(v, _)| *v == version)
    }

    /// The highest version this field has an explicit tag for.
    pub fn max_tag_version(&self) -> u32 {
        self.entries.iter().map(|(v, _)| *v).max().unwrap_or(0)
    }
}

/// Advance one field forward by one version step, in place — the body of
/// go's `migrate()` loop (`config/migrate.go:39`) for a single field,
/// generalized over `T`. Only fires when `history` has an explicit tag at
/// `next_version` (mirrors `hasTag`) AND `*current` is still exactly equal
/// to what the default would have been at `cur_version` (mirrors go's
/// per-kind `reflect.Value...Int()/Bool()/String()` equality check) — i.e.
/// the operator never explicitly overrode this field away from its old
/// default. An explicit override is therefore preserved across every
/// future version step, forever.
fn migrate_field<T: Default + PartialEq>(
    current: &mut T,
    history: &VersionedDefault<T>,
    cur_version: u32,
    next_version: u32,
) {
    if !history.has_tag(next_version) {
        return;
    }
    let default_at_current = history.at(cur_version);
    if *current == default_at_current {
        *current = history.at(next_version);
    }
}

// --- Per-field version histories -------------------------------------------
//
// Real go-algorand fields keep go's exact field name (for `#[serde(rename)]`)
// and exact version-tag boundaries, so an operator's real `config.json`
// value for these fields carries the same meaning at the same version
// number in both implementations. algod-rust-only fields (no go equivalent)
// get a single version-0 entry.

/// Go: `MaxConnectionsPerIP int` `version[3]:"30" version[27]:"15" version[35]:"8"`
/// (`localTemplate.go:68`).
static MAX_CONNECTIONS_PER_IP: VersionedDefault<i64> =
    VersionedDefault::new(&[(3, || 30), (27, || 15), (35, || 8)]);

/// Go: `IncomingConnectionsLimit int` `version[0]:"-1" version[1]:"10000"
/// version[17]:"800" version[27]:"2400"` (`localTemplate.go:107`).
static INCOMING_CONNECTIONS_LIMIT: VersionedDefault<i64> =
    VersionedDefault::new(&[(0, || -1), (1, || 10_000), (17, || 800), (27, || 2_400)]);

/// Go: `EnableP2P bool` `version[31]:"false"` (`localTemplate.go:619`).
static ENABLE_P2P: VersionedDefault<bool> = VersionedDefault::new(&[(31, || false)]);

/// Go: `EnableP2PHybridMode bool` `version[34]:"false"` (`localTemplate.go:624`).
static ENABLE_P2P_HYBRID_MODE: VersionedDefault<bool> = VersionedDefault::new(&[(34, || false)]);

/// Go: `P2PPersistPeerID bool` `version[29]:"false"` (`localTemplate.go:642`).
static P2P_PERSIST_PEER_ID: VersionedDefault<bool> = VersionedDefault::new(&[(29, || false)]);

/// Go: `GossipFanout int` `version[0]:"4"` (`localTemplate.go:52`).
static GOSSIP_FANOUT: VersionedDefault<i64> = VersionedDefault::new(&[(0, || 4)]);

/// Go: `BroadcastConnectionsLimit int` `version[4]:"-1"` (`localTemplate.go:148`).
/// `-1` means unbounded — issue #748 fixed algod-rust's prior hardcoded `35`
/// default, which diverged from go's real (unbounded) default.
static BROADCAST_CONNECTIONS_LIMIT: VersionedDefault<i64> = VersionedDefault::new(&[(4, || -1)]);

/// Go: `ConnectionsRateLimitingCount uint` `version[4]:"60"` (`localTemplate.go:351`).
static CONNECTIONS_RATE_LIMITING_COUNT: VersionedDefault<u64> =
    VersionedDefault::new(&[(4, || 60)]);

/// Go: `ConnectionsRateLimitingWindowSeconds uint` `version[4]:"1"`
/// (`localTemplate.go:345`).
static CONNECTIONS_RATE_LIMITING_WINDOW_SECONDS: VersionedDefault<u64> =
    VersionedDefault::new(&[(4, || 1)]);

/// Go: `TLSCertFile string` `version[0]:""` (`localTemplate.go:74`).
static TLS_CERT_FILE: VersionedDefault<String> = VersionedDefault::new(&[(0, || String::new())]);

/// Go: `TLSKeyFile string` `version[0]:""` (`localTemplate.go:77`).
static TLS_KEY_FILE: VersionedDefault<String> = VersionedDefault::new(&[(0, || String::new())]);

/// Go: `DisableAPIAuth bool` `version[30]:"false"` (`localTemplate.go:650`).
static DISABLE_API_AUTH: VersionedDefault<bool> = VersionedDefault::new(&[(30, || false)]);

/// Go: `EnableGossipService bool` `version[33]:"true"` (`localTemplate.go:407`).
static ENABLE_GOSSIP_SERVICE: VersionedDefault<bool> = VersionedDefault::new(&[(33, || true)]);

/// Go: `EnableLedgerService bool` `version[7]:"false"` (`localTemplate.go:411`).
/// algod-rust has no ledger-serving HTTP service yet (no equivalent to go's
/// `LedgerService` full-ledger/catchpoint-over-the-wire endpoint) — this
/// field round-trips through `config.json` for parity but is a documented
/// no-op until that service exists.
static ENABLE_LEDGER_SERVICE: VersionedDefault<bool> = VersionedDefault::new(&[(7, || false)]);

/// Go: `EnableBlockService bool` `version[7]:"false"` (`localTemplate.go:415`).
static ENABLE_BLOCK_SERVICE: VersionedDefault<bool> = VersionedDefault::new(&[(7, || false)]);

/// Go: `EnableGossipBlockService bool` `version[8]:"true"` (`localTemplate.go:419`).
static ENABLE_GOSSIP_BLOCK_SERVICE: VersionedDefault<bool> = VersionedDefault::new(&[(8, || true)]);

/// Go: `BlockServiceMemCap uint64` `version[28]:"500000000"` (`localTemplate.go:616`).
/// This is a literal byte count (500,000,000 decimal), not `500 * 1024 *
/// 1024` — issue #748 fixed algod-rust's prior binary-MiB interpretation,
/// which diverged from go's exact byte count.
static BLOCK_SERVICE_MEM_CAP: VersionedDefault<u64> =
    VersionedDefault::new(&[(28, || 500_000_000)]);

/// Go: `ForceRelayMessages bool` `version[0]:"false"` (`localTemplate.go:340`).
static FORCE_RELAY_MESSAGES: VersionedDefault<bool> = VersionedDefault::new(&[(0, || false)]);

/// Go: `DNSBootstrapID string` `version[0]:"<network>.algorand.network"
/// version[28]:"<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)"`
/// (`localTemplate.go:188`). The `<network>`/`<name>` placeholders are
/// substituted by the DNS-bootstrap resolution code, not here.
static DNS_BOOTSTRAP_ID: VersionedDefault<String> = VersionedDefault::new(&[
    (0, || "<network>.algorand.network".to_string()),
    (28, || {
        "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)".to_string()
    }),
]);

fn default_version() -> u32 {
    // Mirrors go's explicit `c.Version = 0 // Reset to 0 so we get the
    // version from the loaded file` (config.go:124) — a `version` key
    // absent from the JSON means "this file predates versioning", not
    // "assume the latest version".
    0
}
fn default_max_connections_per_ip() -> i64 {
    MAX_CONNECTIONS_PER_IP.at(LATEST_VERSION)
}
fn default_incoming_connections_limit() -> i64 {
    INCOMING_CONNECTIONS_LIMIT.at(LATEST_VERSION)
}
fn default_enable_p2p() -> bool {
    ENABLE_P2P.at(LATEST_VERSION)
}
fn default_enable_p2p_hybrid_mode() -> bool {
    ENABLE_P2P_HYBRID_MODE.at(LATEST_VERSION)
}
fn default_p2p_persist_peer_id() -> bool {
    P2P_PERSIST_PEER_ID.at(LATEST_VERSION)
}
fn default_gossip_fanout() -> i64 {
    GOSSIP_FANOUT.at(LATEST_VERSION)
}
fn default_broadcast_connections_limit() -> i64 {
    BROADCAST_CONNECTIONS_LIMIT.at(LATEST_VERSION)
}
fn default_connections_rate_limiting_count() -> u64 {
    CONNECTIONS_RATE_LIMITING_COUNT.at(LATEST_VERSION)
}
fn default_connections_rate_limiting_window_seconds() -> u64 {
    CONNECTIONS_RATE_LIMITING_WINDOW_SECONDS.at(LATEST_VERSION)
}
fn default_tls_cert_file() -> String {
    TLS_CERT_FILE.at(LATEST_VERSION)
}
fn default_tls_key_file() -> String {
    TLS_KEY_FILE.at(LATEST_VERSION)
}
fn default_disable_api_auth() -> bool {
    DISABLE_API_AUTH.at(LATEST_VERSION)
}
fn default_enable_gossip_service() -> bool {
    ENABLE_GOSSIP_SERVICE.at(LATEST_VERSION)
}
fn default_enable_ledger_service() -> bool {
    ENABLE_LEDGER_SERVICE.at(LATEST_VERSION)
}
fn default_enable_block_service() -> bool {
    ENABLE_BLOCK_SERVICE.at(LATEST_VERSION)
}
fn default_enable_gossip_block_service() -> bool {
    ENABLE_GOSSIP_BLOCK_SERVICE.at(LATEST_VERSION)
}
fn default_block_service_mem_cap() -> u64 {
    BLOCK_SERVICE_MEM_CAP.at(LATEST_VERSION)
}
fn default_force_relay_messages() -> bool {
    FORCE_RELAY_MESSAGES.at(LATEST_VERSION)
}
fn default_dns_bootstrap_id() -> String {
    DNS_BOOTSTRAP_ID.at(LATEST_VERSION)
}

/// `config.Local`-equivalent node configuration, loaded from `config.json`
/// as a partial overlay onto version-tagged defaults. See the module docs
/// for the mechanism and how to add a field.
///
/// Field-level `#[serde(default = "...")]` (rather than a struct-level
/// `#[serde(default)]`) is what gives every field its own correct
/// "value when absent from the JSON" — each one falls back to its own
/// latest-version default, except `version` itself, which falls back to
/// `0`, matching go's explicit reset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Local {
    /// Tracks which version of the defaults this config was last migrated
    /// to. Go: `Local.Version` (`localTemplate.go:46`).
    #[serde(rename = "Version", default = "default_version")]
    pub version: u32,

    /// Go: `MaxConnectionsPerIP`. Wired into `algo-network`'s
    /// `WebsocketNetworkConfig::max_connections_per_ip` on both `relay` and
    /// `participate` (issue #748).
    #[serde(
        rename = "MaxConnectionsPerIP",
        default = "default_max_connections_per_ip"
    )]
    pub max_connections_per_ip: i64,

    /// Go: `IncomingConnectionsLimit`. Wired into
    /// `WebsocketNetworkConfig::incoming_connections_limit` — see
    /// `max_connections_per_ip`'s note.
    #[serde(
        rename = "IncomingConnectionsLimit",
        default = "default_incoming_connections_limit"
    )]
    pub incoming_connections_limit: i64,

    /// Go: `EnableP2P`.
    #[serde(rename = "EnableP2P", default = "default_enable_p2p")]
    pub enable_p2p: bool,

    /// Go: `EnableP2PHybridMode`.
    #[serde(
        rename = "EnableP2PHybridMode",
        default = "default_enable_p2p_hybrid_mode"
    )]
    pub enable_p2p_hybrid_mode: bool,

    /// Go: `P2PPersistPeerID`.
    #[serde(rename = "P2PPersistPeerID", default = "default_p2p_persist_peer_id")]
    pub p2p_persist_peer_id: bool,

    /// Go: `GossipFanout`. Target number of outgoing gossip peers.
    #[serde(rename = "GossipFanout", default = "default_gossip_fanout")]
    pub gossip_fanout: i64,

    /// Go: `BroadcastConnectionsLimit`. `-1` means unbounded. Wired into
    /// `WebsocketNetworkConfig::broadcast_connections_limit` (issue #748
    /// fixed algod-rust's prior hardcoded `35` default, which diverged
    /// from go's real unbounded-by-default behavior).
    #[serde(
        rename = "BroadcastConnectionsLimit",
        default = "default_broadcast_connections_limit"
    )]
    pub broadcast_connections_limit: i64,

    /// Go: `ConnectionsRateLimitingCount`.
    #[serde(
        rename = "ConnectionsRateLimitingCount",
        default = "default_connections_rate_limiting_count"
    )]
    pub connections_rate_limiting_count: u64,

    /// Go: `ConnectionsRateLimitingWindowSeconds`. Previously entirely
    /// absent from algod-rust, which only modeled the *count* half of this
    /// pair (issue #748).
    #[serde(
        rename = "ConnectionsRateLimitingWindowSeconds",
        default = "default_connections_rate_limiting_window_seconds"
    )]
    pub connections_rate_limiting_window_seconds: u64,

    /// Go: `TLSCertFile`. Wired into both `relay` and `participate` (the
    /// latter previously had no TLS knob at all — issue #748).
    #[serde(rename = "TLSCertFile", default = "default_tls_cert_file")]
    pub tls_cert_file: String,

    /// Go: `TLSKeyFile`. See `tls_cert_file`'s note.
    #[serde(rename = "TLSKeyFile", default = "default_tls_key_file")]
    pub tls_key_file: String,

    /// Go: `DisableAPIAuth`. Wired into `algo-rest-api`'s router: when set,
    /// the public (non-admin) API token check is skipped, matching go's own
    /// "non-admin only" scope for this knob — admin endpoints still always
    /// require the admin token.
    #[serde(rename = "DisableAPIAuth", default = "default_disable_api_auth")]
    pub disable_api_auth: bool,

    /// Go: `EnableGossipService`. Wired: when `false`, the gossip WS
    /// listener is not opened even if a listen address is configured.
    #[serde(
        rename = "EnableGossipService",
        default = "default_enable_gossip_service"
    )]
    pub enable_gossip_service: bool,

    /// Go: `EnableLedgerService`. **Documented no-op**: algod-rust has no
    /// ledger-serving HTTP service to gate yet (see this field's
    /// `VersionedDefault` doc comment). Round-trips through `config.json`
    /// for forward compatibility; wiring is deferred to whichever follow-up
    /// issue implements the underlying service.
    #[serde(
        rename = "EnableLedgerService",
        default = "default_enable_ledger_service"
    )]
    pub enable_ledger_service: bool,

    /// Go: `EnableBlockService`. **Deliberately not wired to gate the HTTP
    /// block-fetch route** (`/v{n}/{genesisID}/block/{round}`), unlike go
    /// where this route is a secondary/archival path: in algod-rust's
    /// actual architecture that same route is the primary relay-to-relay
    /// and `sync`-to-relay catchup mechanism (`bin/algod-rust/src/
    /// commands/{relay,sync}.rs`), so honoring go's real default (`false`)
    /// would silently break block catchup for anyone who didn't know to
    /// flip this on — a regression risk judged not worth taking for a
    /// config-parity field alone (issue #748). The field still round-trips
    /// through `config.json` for forward compatibility. `EnableGossipService`/
    /// `EnableGossipBlockService` below are the fields actually wired to
    /// gate real behavior.
    #[serde(
        rename = "EnableBlockService",
        default = "default_enable_block_service"
    )]
    pub enable_block_service: bool,

    /// Go: `EnableGossipBlockService`. Wired: gates whether the
    /// `UniEnsBlockReq` gossip-tag handler is registered.
    #[serde(
        rename = "EnableGossipBlockService",
        default = "default_enable_gossip_block_service"
    )]
    pub enable_gossip_block_service: bool,

    /// Go: `BlockServiceMemCap`. Wired into
    /// `WebsocketNetworkConfig::block_service_mem_cap`'s default (issue
    /// #748 fixed a prior binary-MiB-vs-decimal-byte-count divergence).
    #[serde(
        rename = "BlockServiceMemCap",
        default = "default_block_service_mem_cap"
    )]
    pub block_service_mem_cap: u64,

    /// Go: `ForceRelayMessages`: relay (forward) gossip messages even when
    /// no listen address is configured. Wired into
    /// `WebsocketNetworkConfig::relay_messages` alongside the existing
    /// `--relay-messages` CLI flag on `participate` (issue #748 also fixed
    /// a related bug: the WS listener previously refused to bind when a
    /// listen address was set but this flag was `false`, which does not
    /// match go's `IsListenServer`-only listener gating).
    #[serde(
        rename = "ForceRelayMessages",
        default = "default_force_relay_messages"
    )]
    pub force_relay_messages: bool,

    /// Go: `DNSBootstrapID`. Wired into `relay`/`participate`/`sync
    /// --gossip`, generalizing the DNS-bootstrap template beyond the
    /// `observe` subcommand it was previously confined to (issue #748).
    #[serde(rename = "DNSBootstrapID", default = "default_dns_bootstrap_id")]
    pub dns_bootstrap_id: String,
}

impl Default for Local {
    /// go's `defaultLocal`: fully materialized at the latest known version.
    fn default() -> Self {
        Self::default_at_version(LATEST_VERSION)
    }
}

impl Local {
    /// What every field's default would be at `version`, replaying each
    /// field's version tags in order — go's `GetVersionedDefaultLocalConfig`
    /// (`config/migrate.go:181`).
    pub fn default_at_version(version: u32) -> Self {
        Self {
            version,
            max_connections_per_ip: MAX_CONNECTIONS_PER_IP.at(version),
            incoming_connections_limit: INCOMING_CONNECTIONS_LIMIT.at(version),
            enable_p2p: ENABLE_P2P.at(version),
            enable_p2p_hybrid_mode: ENABLE_P2P_HYBRID_MODE.at(version),
            p2p_persist_peer_id: P2P_PERSIST_PEER_ID.at(version),
            gossip_fanout: GOSSIP_FANOUT.at(version),
            broadcast_connections_limit: BROADCAST_CONNECTIONS_LIMIT.at(version),
            connections_rate_limiting_count: CONNECTIONS_RATE_LIMITING_COUNT.at(version),
            connections_rate_limiting_window_seconds: CONNECTIONS_RATE_LIMITING_WINDOW_SECONDS
                .at(version),
            tls_cert_file: TLS_CERT_FILE.at(version),
            tls_key_file: TLS_KEY_FILE.at(version),
            disable_api_auth: DISABLE_API_AUTH.at(version),
            enable_gossip_service: ENABLE_GOSSIP_SERVICE.at(version),
            enable_ledger_service: ENABLE_LEDGER_SERVICE.at(version),
            enable_block_service: ENABLE_BLOCK_SERVICE.at(version),
            enable_gossip_block_service: ENABLE_GOSSIP_BLOCK_SERVICE.at(version),
            block_service_mem_cap: BLOCK_SERVICE_MEM_CAP.at(version),
            force_relay_messages: FORCE_RELAY_MESSAGES.at(version),
            dns_bootstrap_id: DNS_BOOTSTRAP_ID.at(version),
        }
    }

    /// Walk this config forward from its current `version` to
    /// [`LATEST_VERSION`], one version at a time — go's `migrate()`
    /// (`config/migrate.go:39`). At each step, a field advances to the new
    /// version's tagged default only if it is still exactly equal to what
    /// the default would have been at the *current* (pre-step) version —
    /// i.e. the operator never explicitly overrode it away from its old
    /// default. An explicit override is preserved unchanged forever, even
    /// across many version steps.
    ///
    /// Returns [`ConfigError::VersionTooNew`] if `self.version` is already
    /// beyond `LATEST_VERSION` (an untrusted or hand-edited `config.json`
    /// claiming a future version this binary doesn't understand) — mirrors
    /// go's own guard rather than silently truncating or panicking.
    pub fn migrate(&mut self) -> Result<(), ConfigError> {
        if self.version > LATEST_VERSION {
            return Err(ConfigError::VersionTooNew {
                found: self.version,
                latest: LATEST_VERSION,
            });
        }
        while self.version < LATEST_VERSION {
            let cur = self.version;
            let next = cur + 1;
            migrate_field(
                &mut self.max_connections_per_ip,
                &MAX_CONNECTIONS_PER_IP,
                cur,
                next,
            );
            migrate_field(
                &mut self.incoming_connections_limit,
                &INCOMING_CONNECTIONS_LIMIT,
                cur,
                next,
            );
            migrate_field(&mut self.enable_p2p, &ENABLE_P2P, cur, next);
            migrate_field(
                &mut self.enable_p2p_hybrid_mode,
                &ENABLE_P2P_HYBRID_MODE,
                cur,
                next,
            );
            migrate_field(
                &mut self.p2p_persist_peer_id,
                &P2P_PERSIST_PEER_ID,
                cur,
                next,
            );
            migrate_field(&mut self.gossip_fanout, &GOSSIP_FANOUT, cur, next);
            migrate_field(
                &mut self.broadcast_connections_limit,
                &BROADCAST_CONNECTIONS_LIMIT,
                cur,
                next,
            );
            migrate_field(
                &mut self.connections_rate_limiting_count,
                &CONNECTIONS_RATE_LIMITING_COUNT,
                cur,
                next,
            );
            migrate_field(
                &mut self.connections_rate_limiting_window_seconds,
                &CONNECTIONS_RATE_LIMITING_WINDOW_SECONDS,
                cur,
                next,
            );
            migrate_field(&mut self.tls_cert_file, &TLS_CERT_FILE, cur, next);
            migrate_field(&mut self.tls_key_file, &TLS_KEY_FILE, cur, next);
            migrate_field(&mut self.disable_api_auth, &DISABLE_API_AUTH, cur, next);
            migrate_field(
                &mut self.enable_gossip_service,
                &ENABLE_GOSSIP_SERVICE,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_ledger_service,
                &ENABLE_LEDGER_SERVICE,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_block_service,
                &ENABLE_BLOCK_SERVICE,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_gossip_block_service,
                &ENABLE_GOSSIP_BLOCK_SERVICE,
                cur,
                next,
            );
            migrate_field(
                &mut self.block_service_mem_cap,
                &BLOCK_SERVICE_MEM_CAP,
                cur,
                next,
            );
            migrate_field(
                &mut self.force_relay_messages,
                &FORCE_RELAY_MESSAGES,
                cur,
                next,
            );
            migrate_field(&mut self.dns_bootstrap_id, &DNS_BOOTSTRAP_ID, cur, next);
            self.version = next;
        }
        Ok(())
    }

    /// Parse `config.json` content as a partial overlay onto
    /// version-tagged defaults, then [`migrate`](Self::migrate) it
    /// forward. This is the JSON-decode-onto-prepopulated-defaults +
    /// migrate sequence from go's `loadConfigFromFile`
    /// (`config/config.go:122`), minus `enrichNetworkingConfig` (out of
    /// scope for this issue — see the module docs).
    pub fn load_from_str(text: &str) -> Result<Self, ConfigError> {
        let mut cfg: Self = serde_json::from_str(text).map_err(|source| ConfigError::Parse {
            path: PathBuf::from("<string>"),
            source,
        })?;
        cfg.migrate()?;
        Ok(cfg)
    }

    /// Load and migrate a `config.json` file at an exact path.
    pub fn load_from_path(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut cfg: Self = serde_json::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        cfg.migrate()?;
        Ok(cfg)
    }

    /// Load `<data_dir>/config.json`, matching go's
    /// `LoadConfigFromDisk(custom)` (`config/config.go:112`, which joins
    /// `custom` with [`CONFIG_FILENAME`]). A missing file is not an error —
    /// it returns [`Local::default`] (fully materialized at
    /// [`LATEST_VERSION`], nothing to migrate), matching "no config.json
    /// yet" being the common case for a brand new data directory. Any
    /// other I/O error (permissions, etc.) or a malformed/future-versioned
    /// file is returned as an error rather than silently falling back, so
    /// a genuinely broken config.json is never masked as "just use
    /// defaults".
    pub fn load_from_data_dir(data_dir: &Path) -> Result<Self, ConfigError> {
        let path = data_dir.join(CONFIG_FILENAME);
        match fs::read_to_string(&path) {
            Ok(text) => {
                let mut cfg: Self =
                    serde_json::from_str(&text).map_err(|source| ConfigError::Parse {
                        path: path.clone(),
                        source,
                    })?;
                cfg.migrate()?;
                Ok(cfg)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Io { path, source }),
        }
    }

    /// Serialize every field, mirroring go's `SaveAllToDisk`
    /// (`localTemplate.go:715`).
    pub fn to_json_full(&self) -> Result<String, ConfigError> {
        serde_json::to_string_pretty(self).map_err(ConfigError::Encode)
    }

    /// Serialize only the fields that differ from [`Local::default`], plus
    /// `Version` unconditionally — go's `SaveNonDefaultValuesToFile`
    /// (`localTemplate.go:722`, called with `alwaysInclude = ["Version"]`).
    /// Achieved generically (works automatically as fields are added, with
    /// no per-field hand-maintenance) by comparing this config's
    /// `serde_json::Value` against the default's, key by key.
    pub fn to_json_minimized(&self) -> Result<String, ConfigError> {
        let full = serde_json::to_value(self).map_err(ConfigError::Encode)?;
        let default = serde_json::to_value(Self::default()).map_err(ConfigError::Encode)?;
        let (serde_json::Value::Object(full_map), serde_json::Value::Object(default_map)) =
            (full, default)
        else {
            unreachable!("Local always serializes to a JSON object")
        };
        let mut out = serde_json::Map::new();
        for (key, value) in full_map {
            if key == "Version" || default_map.get(&key) != Some(&value) {
                out.insert(key, value);
            }
        }
        serde_json::to_string_pretty(&serde_json::Value::Object(out)).map_err(ConfigError::Encode)
    }

    /// Write [`Local::to_json_minimized`]'s output to `path`.
    pub fn save_non_default_to_path(&self, path: &Path) -> Result<(), ConfigError> {
        let json = self.to_json_minimized()?;
        fs::write(path, json).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field's version history must top out at or below
    /// [`LATEST_VERSION`] — and at least one field must reach it exactly,
    /// so the constant can't silently drift stale as fields are added
    /// (mirrors go's own `!!! WARNING !!!` comment requiring `Version`'s
    /// own tag list to be updated in lockstep).
    #[test]
    fn latest_version_matches_max_field_tag() {
        let max_tag = [
            MAX_CONNECTIONS_PER_IP.max_tag_version(),
            INCOMING_CONNECTIONS_LIMIT.max_tag_version(),
            ENABLE_P2P.max_tag_version(),
            ENABLE_P2P_HYBRID_MODE.max_tag_version(),
            P2P_PERSIST_PEER_ID.max_tag_version(),
            GOSSIP_FANOUT.max_tag_version(),
            BROADCAST_CONNECTIONS_LIMIT.max_tag_version(),
            CONNECTIONS_RATE_LIMITING_COUNT.max_tag_version(),
            CONNECTIONS_RATE_LIMITING_WINDOW_SECONDS.max_tag_version(),
            TLS_CERT_FILE.max_tag_version(),
            TLS_KEY_FILE.max_tag_version(),
            DISABLE_API_AUTH.max_tag_version(),
            ENABLE_GOSSIP_SERVICE.max_tag_version(),
            ENABLE_LEDGER_SERVICE.max_tag_version(),
            ENABLE_BLOCK_SERVICE.max_tag_version(),
            ENABLE_GOSSIP_BLOCK_SERVICE.max_tag_version(),
            BLOCK_SERVICE_MEM_CAP.max_tag_version(),
            FORCE_RELAY_MESSAGES.max_tag_version(),
            DNS_BOOTSTRAP_ID.max_tag_version(),
        ]
        .into_iter()
        .max()
        .unwrap();
        assert_eq!(max_tag, LATEST_VERSION);
    }

    #[test]
    fn default_is_fully_materialized_at_latest_version() {
        let d = Local::default();
        assert_eq!(d.version, LATEST_VERSION);
        assert_eq!(d.max_connections_per_ip, 8);
        assert_eq!(d.incoming_connections_limit, 2_400);
        assert!(!d.enable_p2p);
        assert!(!d.enable_p2p_hybrid_mode);
        assert!(!d.p2p_persist_peer_id);
        assert_eq!(d.gossip_fanout, 4);
        assert_eq!(
            d.broadcast_connections_limit, -1,
            "go's real default is unbounded (-1), not algod-rust's old hardcoded 35"
        );
        assert_eq!(d.connections_rate_limiting_count, 60);
        assert_eq!(d.connections_rate_limiting_window_seconds, 1);
        assert_eq!(d.tls_cert_file, "");
        assert_eq!(d.tls_key_file, "");
        assert!(!d.disable_api_auth);
        assert!(d.enable_gossip_service);
        assert!(!d.enable_ledger_service);
        assert!(!d.enable_block_service);
        assert!(d.enable_gossip_block_service);
        assert_eq!(
            d.block_service_mem_cap, 500_000_000,
            "go's literal byte count, not a binary-MiB approximation"
        );
        assert!(!d.force_relay_messages);
        assert_eq!(
            d.dns_bootstrap_id,
            "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)"
        );
    }

    #[test]
    fn default_at_version_replays_only_tags_up_to_that_version() {
        // Before MaxConnectionsPerIP's first tag (version 3), the field's
        // "default" is the Rust zero value, exactly like Go's untagged
        // zero value.
        let at0 = Local::default_at_version(0);
        assert_eq!(at0.max_connections_per_ip, 0);
        assert_eq!(at0.incoming_connections_limit, -1);
        assert_eq!(at0.gossip_fanout, 4);
        assert_eq!(
            at0.broadcast_connections_limit, 0,
            "BroadcastConnectionsLimit has no tag before version 4"
        );
        assert_eq!(at0.dns_bootstrap_id, "<network>.algorand.network");

        let at3 = Local::default_at_version(3);
        assert_eq!(at3.max_connections_per_ip, 30);

        let at27 = Local::default_at_version(27);
        assert_eq!(at27.max_connections_per_ip, 15);
        assert_eq!(at27.incoming_connections_limit, 2_400);
        assert_eq!(at27.dns_bootstrap_id, "<network>.algorand.network");

        let at28 = Local::default_at_version(28);
        assert_eq!(at28.block_service_mem_cap, 500_000_000);
        assert_eq!(
            at28.dns_bootstrap_id,
            "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)"
        );

        let at34 = Local::default_at_version(34);
        assert_eq!(at34.max_connections_per_ip, 15);
        assert!(!at34.enable_p2p_hybrid_mode);
    }

    // --- Partial JSON overlay ------------------------------------------

    #[test]
    fn empty_json_object_loads_every_field_at_its_versioned_default() {
        let cfg = Local::load_from_str("{}").expect("empty object parses");
        // No "Version" key => go's explicit reset to 0, then migrate()
        // walks it all the way forward, landing on the same values as
        // Local::default() (nothing was ever an explicit override).
        assert_eq!(cfg, Local::default());
    }

    #[test]
    fn json_partial_overlay_only_overrides_present_fields() {
        let cfg = Local::load_from_str(r#"{"EnableP2P": true}"#).expect("partial object parses");
        assert!(cfg.enable_p2p);
        // Everything else present in the file? No — verify it still
        // carries its versioned default, not some zeroed/garbage value.
        assert_eq!(cfg.max_connections_per_ip, 8);
        assert_eq!(cfg.incoming_connections_limit, 2_400);
        assert!(!cfg.enable_p2p_hybrid_mode);
        assert!(!cfg.p2p_persist_peer_id);
        assert_eq!(cfg.broadcast_connections_limit, -1);
    }

    #[test]
    fn string_field_partial_overlay_only_overrides_present_field() {
        let cfg = Local::load_from_str(r#"{"TLSCertFile": "/etc/algod/cert.pem"}"#)
            .expect("partial object parses");
        assert_eq!(cfg.tls_cert_file, "/etc/algod/cert.pem");
        // TLSKeyFile untouched — still its versioned default (empty).
        assert_eq!(cfg.tls_key_file, "");
    }

    // --- Version migration: the core TDD target of this issue ----------

    #[test]
    fn field_still_at_old_default_advances_to_new_default_across_multiple_boundaries() {
        // A config.json written by an old algod-rust build: explicit
        // Version 1, IncomingConnectionsLimit left at version 1's own
        // default (10_000) — i.e. never touched by the operator.
        let cfg = Local::load_from_str(r#"{"Version": 1, "IncomingConnectionsLimit": 10000}"#)
            .expect("parses");
        // migrate() must walk it through the 17 and 27 boundaries to the
        // latest default (2_400), NOT leave it at 10_000.
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(cfg.incoming_connections_limit, 2_400);
    }

    #[test]
    fn field_explicitly_overridden_away_from_default_is_never_clobbered() {
        // Same starting version, but the operator explicitly chose 50_000
        // — nowhere close to any version's default.
        let cfg = Local::load_from_str(r#"{"Version": 1, "IncomingConnectionsLimit": 50000}"#)
            .expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(
            cfg.incoming_connections_limit, 50_000,
            "an explicit non-default override must survive every future version's migration"
        );
    }

    #[test]
    fn field_at_default_that_happens_to_match_a_later_versions_default_still_advances() {
        // Starting at version 26 (just before MaxConnectionsPerIP's 27
        // boundary), with the field explicitly present at version 27's
        // pre-27 default (30, from the version-3 tag) — i.e. unmodified.
        let cfg =
            Local::load_from_str(r#"{"Version": 26, "MaxConnectionsPerIP": 30}"#).expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        // Must walk through 27 (-> 15) and 35 (-> 8), landing on 8, not
        // getting stuck at 30 or stopping at the intermediate 15.
        assert_eq!(cfg.max_connections_per_ip, 8);
    }

    #[test]
    fn missing_version_key_is_treated_as_version_zero() {
        // No "Version" key at all (predates versioning entirely) with
        // IncomingConnectionsLimit at version 0's default (-1).
        let cfg = Local::load_from_str(r#"{"IncomingConnectionsLimit": -1}"#).expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(cfg.incoming_connections_limit, 2_400);
    }

    #[test]
    fn version_newer_than_latest_known_is_rejected_not_panicked() {
        let err = Local::load_from_str(r#"{"Version": 999999}"#).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::VersionTooNew {
                found: 999_999,
                latest: LATEST_VERSION
            }
        ));
    }

    #[test]
    fn string_field_migration_preserves_explicit_override() {
        // DNSBootstrapID explicitly set to something other than any
        // version's default must never be clobbered by migrate().
        let cfg = Local::load_from_str(r#"{"Version": 0, "DNSBootstrapID": "custom.example.net"}"#)
            .expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(cfg.dns_bootstrap_id, "custom.example.net");
    }

    #[test]
    fn string_field_migration_advances_when_left_at_old_default() {
        // DNSBootstrapID left at version 0's default must advance to
        // version 28's template across the migration.
        let cfg = Local::load_from_str(
            r#"{"Version": 0, "DNSBootstrapID": "<network>.algorand.network"}"#,
        )
        .expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(
            cfg.dns_bootstrap_id,
            "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)"
        );
    }

    // --- File loading ----------------------------------------------------

    #[test]
    fn missing_config_json_in_data_dir_returns_defaults() {
        let dir = std::env::temp_dir().join(format!(
            "algo-config-test-missing-{}-{}",
            std::process::id(),
            line!()
        ));
        // Deliberately do not create `dir` or any file in it.
        let cfg = Local::load_from_data_dir(&dir).expect("missing file is not an error");
        assert_eq!(cfg, Local::default());
    }

    #[test]
    fn malformed_config_json_is_a_parse_error_not_a_panic() {
        let dir = std::env::temp_dir().join(format!(
            "algo-config-test-malformed-{}-{}",
            std::process::id(),
            line!()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(CONFIG_FILENAME), b"not json").unwrap();
        let err = Local::load_from_data_dir(&dir).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn real_config_json_round_trips_through_data_dir() {
        let dir = std::env::temp_dir().join(format!(
            "algo-config-test-roundtrip-{}-{}",
            std::process::id(),
            line!()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(CONFIG_FILENAME),
            r#"{"Version": 30, "EnableP2P": true, "MaxConnectionsPerIP": 15}"#,
        )
        .unwrap();
        let cfg = Local::load_from_data_dir(&dir).expect("loads");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert!(cfg.enable_p2p);
        // MaxConnectionsPerIP=15 matches version 27's own default, which
        // is what an unmodified field would read at version 30 — so it
        // must still advance to the version-35 default (8).
        assert_eq!(cfg.max_connections_per_ip, 8);
        let _ = fs::remove_dir_all(&dir);
    }

    // --- Minimized save ----------------------------------------------------

    #[test]
    fn save_non_default_only_includes_version_and_overridden_fields() {
        let cfg = Local {
            enable_p2p: true,
            ..Local::default()
        };
        let json = cfg.to_json_minimized().expect("serializes");
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(
            obj.get("Version").and_then(|v| v.as_u64()),
            Some(LATEST_VERSION as u64)
        );
        assert_eq!(obj.get("EnableP2P").and_then(|v| v.as_bool()), Some(true));
        // Every other field is at its default, so must be omitted.
        assert!(!obj.contains_key("MaxConnectionsPerIP"));
        assert!(!obj.contains_key("IncomingConnectionsLimit"));
        assert!(!obj.contains_key("EnableP2PHybridMode"));
        assert!(!obj.contains_key("P2PPersistPeerID"));
        assert!(!obj.contains_key("TLSCertFile"));
        assert!(!obj.contains_key("BroadcastConnectionsLimit"));
    }

    #[test]
    fn save_non_default_round_trips_back_to_the_same_config() {
        let cfg = Local {
            max_connections_per_ip: 42,
            tls_cert_file: "/etc/algod/cert.pem".to_string(),
            ..Local::default()
        };
        let json = cfg.to_json_minimized().expect("serializes");
        let reloaded = Local::load_from_str(&json).expect("parses back");
        assert_eq!(reloaded, cfg);
    }

    #[test]
    fn default_config_minimizes_to_just_version() {
        let json = Local::default().to_json_minimized().expect("serializes");
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.len(), 1);
        assert!(obj.contains_key("Version"));
    }
}
