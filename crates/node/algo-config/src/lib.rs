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
//! - `enrichNetworkingConfig`'s field-level post-load normalization.
//!   Issue #788 (the "#748 follow-up" this note used to point at) resolved
//!   this: algod-rust deliberately keeps `NetAddress` as a
//!   CLI-flag-per-subcommand concept (`relay --bind-address`, required;
//!   `participate --listen-address`, optional) rather than promoting it to
//!   a `Local` field, because neither of go's other two side effects has a
//!   real behavior to gate here (`EnableLedgerService`/`EnableBlockService`
//!   are already documented no-ops; `PublicAddress` is still round-trip
//!   only) — unifying onto a shared field would just relocate, not close,
//!   those gaps. The one side effect that *does* have a real algod-rust
//!   equivalent — the `GossipFanout` bump for a listen-server node — is
//!   implemented as [`Local::gossip_fanout_for_listen_server`], called
//!   explicitly by `relay`/`participate` once each knows it is (or isn't)
//!   acting as a listen server, rather than firing automatically off a
//!   `Local` field that doesn't exist.
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

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub mod algocfg;

/// Filename go-algorand (and algod-rust) reads relative to the node's data
/// directory. Go: `config.ConfigFilename` (`config/config.go:61`).
pub const CONFIG_FILENAME: &str = "config.json";

/// Highest version any field on [`Local`] carries a tag for. Every field's
/// version history in this file must top out at or below this value; the
/// `latest_version_matches_max_field_tag` test enforces that they stay in
/// sync, mirroring go's `!!! WARNING !!!` comment on `Local.Version`
/// ("This field tag must be updated any time we add a new version").
///
/// Bumped from 35 to 38 by issue #768 (`DHTMode` carries `version[38]`
/// upstream, `localTemplate.go:638`) — go's own `Local.Version` struct tag
/// already lists every version through 38 at this repo's `v5.0.0-stable`
/// pin, so this only catches algod-rust's own field set up to what a real
/// field here now needs, not a new upstream version.
pub const LATEST_VERSION: u32 = 38;

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

    /// [`algocfg::get_property`]/[`algocfg::set_property`]/
    /// [`algocfg::reset_property`] were asked about a name that isn't a
    /// [`Local`] field. Go: `"unknown property named '%s'"`
    /// (`cmd/algocfg/getCommand.go:76`, `setCommand.go:87`,
    /// `resetCommand.go:84,92`).
    #[error("unknown property named '{name}'")]
    UnknownProperty { name: String },

    /// [`algocfg::set_property`] was given a value that doesn't parse as
    /// the field's type. Go: the per-`reflect.Kind` parse errors in
    /// `setFieldValue` (`cmd/algocfg/setCommand.go:94`).
    #[error("error setting property '{name}' -> '{value}': {reason}")]
    InvalidPropertyValue {
        name: String,
        value: String,
        reason: String,
    },

    /// [`algocfg::config_for_profile`] was given a name not in
    /// [`algocfg::profile_names`]. Go: `"unknown profile provided: '%s' is
    /// not in list of valid profiles: %s"`
    /// (`cmd/algocfg/profileCommand.go:269`).
    #[error("unknown profile provided: '{name}' is not in list of valid profiles: {valid}")]
    UnknownProfile { name: String, valid: String },
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

/// Go: `CatchpointDir string` `version[31]:""` (`localTemplate.go:114`).
/// Originally adopted from go's 9-field hot/cold directory-splitting group
/// as a judgment-called subset (issue #749) that left
/// `HotDataDir`/`ColdDataDir`/`TrackerDBDir`/`BlockDBDir`/`CrashDBDir` as an
/// explicit architectural non-goal. Issue #953 (Phase 17 test-parity audit)
/// revisited that call: [`HOT_DATA_DIR`]/[`COLD_DATA_DIR`]/
/// [`TRACKER_DB_DIR`]/[`BLOCK_DB_DIR`]/[`CRASH_DB_DIR`] are now added below
/// and wired into `algod-rust participate`'s ledger/crash-db path
/// resolution (`bin/algod-rust/src/commands/participate.rs`'s
/// `resolve_resource_paths`). `CatchpointDir` itself keeps its existing
/// standalone `algod-rust catchpoint export`/`download` wiring
/// (`bin/algod-rust/src/commands/catchpoint.rs`) and is not cross-wired to
/// fall back onto `ColdDataDir` the way go's does — that finer cross-field
/// fallback is out of scope for #953, which only had to close the
/// per-resource *directory override* gap itself.
static CATCHPOINT_DIR: VersionedDefault<String> = VersionedDefault::new(&[(31, || String::new())]);

/// Go: `StateproofDir string` `version[31]:""` (`localTemplate.go:118`).
/// **Documented no-op** (same pattern as `enable_ledger_service`):
/// algod-rust persists state-proof signing secrets as rows inside the
/// existing partkey `ErasableDb` file
/// (`crates/core/algo-ledger/src/participation/stateproof_persist.rs`)
/// rather than a separate stateproof-only database/directory, so there is
/// no distinct location to redirect yet. Round-trips through `config.json`
/// for forward compatibility; real wiring is deferred to whichever future
/// issue splits stateproof persistence into its own storage location.
/// Unaffected by issue #953's `HotDataDir`/`ColdDataDir` addition below —
/// go falls `StateproofDir` back onto `HotDataDir`, but that fallback is
/// meaningless here while this field itself stays a no-op.
static STATEPROOF_DIR: VersionedDefault<String> = VersionedDefault::new(&[(31, || String::new())]);

/// Go: `HotDataDir string` `version[31]:""` (`localTemplate.go:93`). Issue
/// #953: an optional directory for data that is frequently accessed by the
/// node. When set, it becomes the fallback directory for `TrackerDBDir`
/// and `CrashDBDir` (see [`TRACKER_DB_DIR`]/[`CRASH_DB_DIR`]); when unset,
/// the ledger prefix's own directory (`--ledger-path`'s parent) is used,
/// matching today's pre-#953 behavior exactly.
static HOT_DATA_DIR: VersionedDefault<String> = VersionedDefault::new(&[(31, || String::new())]);

/// Go: `ColdDataDir string` `version[31]:""` (`localTemplate.go:100`).
/// Issue #953: an optional directory for data that is infrequently
/// accessed by the node. When set, it becomes the fallback directory for
/// `BlockDBDir` (see [`BLOCK_DB_DIR`]); when unset, the ledger prefix's own
/// directory is used, matching today's pre-#953 behavior exactly.
static COLD_DATA_DIR: VersionedDefault<String> = VersionedDefault::new(&[(31, || String::new())]);

/// Go: `TrackerDBDir string` `version[31]:""` (`localTemplate.go:105`,
/// "If not specified, the node will use the HotDataDir"). Issue #953:
/// overrides the directory `<prefix>.tracker.sqlite` opens in, independent
/// of where the block DB and crash DB live. Falls back to `HotDataDir`.
static TRACKER_DB_DIR: VersionedDefault<String> = VersionedDefault::new(&[(31, || String::new())]);

/// Go: `BlockDBDir string` `version[31]:""` (`localTemplate.go:108`, "If
/// not specified, the node will use the ColdDataDir"). Issue #953:
/// overrides the directory `<prefix>.block.sqlite` opens in. Falls back to
/// `ColdDataDir`.
static BLOCK_DB_DIR: VersionedDefault<String> = VersionedDefault::new(&[(31, || String::new())]);

/// Go: `CrashDBDir string` `version[31]:""` (`localTemplate.go:121`, "If
/// not specified, the node will use the HotDataDir"). Issue #953: overrides
/// the directory the agreement crash-recovery database (`crash.sqlite`)
/// opens in. Falls back to `HotDataDir`.
static CRASH_DB_DIR: VersionedDefault<String> = VersionedDefault::new(&[(31, || String::new())]);

/// Go: `LogFileDir string` `version[31]:""` (`localTemplate.go:125`, "If
/// not specified, the node will use the ColdDataDir"). **Documented
/// no-op**, same pattern as [`STATEPROOF_DIR`]: algod-rust has no
/// file-based log-archival subsystem to redirect (logging currently goes
/// to stdout/tracing subscribers configured at process startup, not a
/// rotated `node.log` file the way go's `logging.CreateGlobalLogger`
/// resolves via `ResolveLogPaths`). Round-trips through `config.json` for
/// forward compatibility; real wiring is deferred to whichever future
/// issue adds file-based log output.
static LOG_FILE_DIR: VersionedDefault<String> = VersionedDefault::new(&[(31, || String::new())]);

/// Go: `LogArchiveDir string` `version[31]:""` (`localTemplate.go:129`, "If
/// not specified, the node will use the ColdDataDir"). **Documented
/// no-op** — see [`LOG_FILE_DIR`]'s doc comment; algod-rust has no
/// log-archival subsystem to redirect either half of.
static LOG_ARCHIVE_DIR: VersionedDefault<String> = VersionedDefault::new(&[(31, || String::new())]);

/// Go: `CatchpointInterval uint64` `version[7]:"10000"` (`localTemplate.go:399`).
/// Wired into the live block-apply loop (issue #770): `SqliteLedger::commit_block`
/// automatically exports a catchpoint file every `CatchpointInterval` rounds
/// when [`Local::stores_catchpoints`] resolves to `true`, matching go's
/// `catchpointTracker` (`ledger/catchpointtracker.go`).
static CATCHPOINT_INTERVAL: VersionedDefault<u64> = VersionedDefault::new(&[(7, || 10_000)]);

/// Go: `CatchpointFileHistoryLength int` `version[7]:"365"` (`localTemplate.go:401`).
/// Wired into the automatic-generation retention/pruning policy (issue
/// #770) — see [`Local::stores_catchpoints`] and
/// `algo_ledger::sqlite::SqliteLedger::configure_automatic_catchpoints`.
static CATCHPOINT_FILE_HISTORY_LENGTH: VersionedDefault<i64> =
    VersionedDefault::new(&[(7, || 365)]);

/// Go: `CatchpointTracking int64` `version[11]:"0"` (`localTemplate.go:447`).
/// Wired into [`Local::stores_catchpoints`]/[`Local::tracks_catchpoints`]
/// (issue #770), which mirror go's `config.Local.StoresCatchpoints`/
/// `TracksCatchpoints` (`config/localTemplate.go:1052-1080`) mode
/// resolution exactly, including the automatic-mode archival gate.
static CATCHPOINT_TRACKING: VersionedDefault<i64> = VersionedDefault::new(&[(11, || 0)]);

/// Go: `Archival bool` `version[0]:"false"` (`localTemplate.go:49`).
///
/// algod-rust does not yet implement go's non-archival block-pruning
/// behavior (`Ledger.setDbLogging`/`trackerRegistry` "forget old blocks"
/// path) — every algod-rust node currently retains its full block
/// history regardless of this flag. This field is added now (issue #770,
/// narrower than a full archival-mode implementation) solely so
/// [`Local::stores_catchpoints`] can reproduce go's exact
/// `CatchpointTrackingModeAutomatic`/`CatchpointTrackingModeTracked`
/// mode-resolution gate (`config/localTemplate.go:1052-1069`), which
/// consults `cfg.Archival` for those two modes. It defaults to `false`,
/// matching go's own default — so a stock config with the default
/// `CatchpointTracking = 0` (automatic) does **not** auto-generate
/// catchpoints, exactly mirroring a stock non-archival go-algorand node.
/// Set `CatchpointTracking = 2` (Stored) to force generation regardless
/// of this flag, or set both `Archival = true` and leave `CatchpointTracking`
/// at its automatic/tracked default.
static ARCHIVAL: VersionedDefault<bool> = VersionedDefault::new(&[(0, || false)]);

/// Go: `OptimizeAccountsDatabaseOnStartup bool` `version[10]:"false"`
/// (`localTemplate.go:439`). Wired into `SqliteLedger::vacuum_accounts_database`
/// (runs SQLite `VACUUM` on the tracker/accounts schema), matching go's
/// `Ledger.reloadLedger` calling `l.accts.vacuumDatabase` when this flag
/// (or a schema-upgrade-triggered `VacuumOnStartup`) is set
/// (`../go-algorand/ledger/ledger.go:268-272`).
static OPTIMIZE_ACCOUNTS_DATABASE_ON_STARTUP: VersionedDefault<bool> =
    VersionedDefault::new(&[(10, || false)]);

/// Go: `LedgerSynchronousMode int` `version[12]:"2"` (`localTemplate.go:455`).
/// `2` = SQLite `PRAGMA synchronous=FULL`. Wired into
/// `SqliteLedger::set_synchronous_mode`, applied to the main ledger
/// connection (tracker + attached block schema).
static LEDGER_SYNCHRONOUS_MODE: VersionedDefault<i64> = VersionedDefault::new(&[(12, || 2)]);

/// Go: `AccountsRebuildSynchronousMode int` `version[12]:"1"`
/// (`localTemplate.go:460`). `1` = SQLite `PRAGMA synchronous=NORMAL`.
/// Wired into the rebuild-shaped connections that bulk-load a fresh
/// accounts snapshot: `open_ledger_connection_with_sync_mode` (catchpoint
/// import/verify) and the catchpoint-sync orchestrator's `open_db`
/// (`crates/core/algo-ledger/src/sync/mod.rs`) — both previously hardcoded
/// `PRAGMA synchronous=NORMAL` unconditionally, matching this field's
/// default but with no way to override it.
static ACCOUNTS_REBUILD_SYNCHRONOUS_MODE: VersionedDefault<i64> =
    VersionedDefault::new(&[(12, || 1)]);

/// Go: `MaxCatchpointDownloadDuration time.Duration` `version[13]:"7200000000000"
/// version[28]:"43200000000000"` (`localTemplate.go:465`). Nanoseconds
/// (go's raw `time.Duration` JSON encoding). Wired into
/// `CatchpointDownloadConfig::timeout` (`algo-rest-client`), which
/// previously hardcoded a 30-minute timeout that matched neither of go's
/// real defaults (2h pre-version-28, 12h from version 28 onward).
static MAX_CATCHPOINT_DOWNLOAD_DURATION: VersionedDefault<i64> =
    VersionedDefault::new(&[(13, || 7_200_000_000_000), (28, || 43_200_000_000_000)]);

/// Go: `MinCatchpointFileDownloadBytesPerSecond uint64` `version[13]:"20480"`
/// (`localTemplate.go:470`). Wired into `CatchpointDownloadConfig`'s
/// per-chunk stall-detection timeout, mirroring (not byte-for-byte
/// replicating) go's `ledgerFetcher.go` watchdog-stream-reader formula.
static MIN_CATCHPOINT_FILE_DOWNLOAD_BYTES_PER_SECOND: VersionedDefault<u64> =
    VersionedDefault::new(&[(13, || 20_480)]);

/// Go: `DisableLedgerLRUCache bool` `version[27]:"false"` (`localTemplate.go:593`).
/// Wired into `MerkleTrieCache`'s eviction: when set, `evict()` becomes a
/// no-op, matching go's "disables LRU caches in ledger... SHOULD NOT be
/// used for other reasons than testing" (performance-degrading by
/// design, not a not-applicable knob — algod-rust's merkle trie page
/// cache is a real LRU implementation, see `merkle_cache.rs`).
static DISABLE_LEDGER_LRU_CACHE: VersionedDefault<bool> = VersionedDefault::new(&[(27, || false)]);

// --- REST/API fields (issue #751) ------------------------------------------

/// Go: `EndpointAddress string` `version[0]:"127.0.0.1:0"`
/// (`localTemplate.go:170`). The headline finding of issue #751: go always
/// starts the REST API server (`daemon/algod/server.go` unconditionally
/// calls `Start`, using this as the bind address — there is no "off"
/// switch upstream), while algod-rust's `--rest-listen` previously had no
/// default at all, meaning "no REST" was the out-of-the-box behavior. No
/// documented rationale for that opt-in default was found anywhere
/// (`cli.rs`'s own doc comment only cited pre-TASK-79 migration inertia) —
/// **decision recorded here: align with go's always-on ephemeral-port
/// default.** `bin/algod-rust/src/commands/participate.rs`'s
/// `RestOptions::resolve` now falls back to this field when neither
/// `--rest-listen` nor `[rest].listen` is set, and treats an *explicit*
/// empty string as an algod-rust-only "disable REST" affordance (go's own
/// `addr == ""` falls back to binding port 80, which is not a real off
/// switch and doesn't fit `participate`'s REST-is-optional architecture).
static ENDPOINT_ADDRESS: VersionedDefault<String> =
    VersionedDefault::new(&[(0, || "127.0.0.1:0".to_string())]);

/// Go: `RestReadTimeoutSeconds int` `version[4]:"15"` (`localTemplate.go:176`).
/// Wired into `ApiServerConfig`/`ApiServer::serve` as an overall
/// per-request timeout alongside `rest_write_timeout_seconds` (see that
/// field's note for why the two collapse into one `tower_http::timeout`
/// layer rather than separate read/write phases).
static REST_READ_TIMEOUT_SECONDS: VersionedDefault<i64> = VersionedDefault::new(&[(4, || 15)]);

/// Go: `RestWriteTimeoutSeconds int` `version[4]:"120"` (`localTemplate.go:179`).
/// go's `net/http.Server` exposes independent `ReadTimeout`/`WriteTimeout`
/// phases; axum/hyper's server builder (`crates/node/algo-rest-api/src/
/// server.rs`) has no equivalent split, so both fields are wired together
/// into a single `tower_http::timeout::TimeoutLayer` bounding total
/// request-to-response time at `max(read, write)` — an approximation
/// documented at the call site, not a byte-for-byte port of go's two-phase
/// timeout.
static REST_WRITE_TIMEOUT_SECONDS: VersionedDefault<i64> = VersionedDefault::new(&[(4, || 120)]);

/// Go: `EnablePrivateNetworkAccessHeader bool` `version[35]:"false"`
/// (`localTemplate.go:173`). Wired into the REST router: when `true`, adds
/// `Access-Control-Allow-Private-Network: true` to CORS preflight
/// responses (Chrome's Private Network Access spec), matching go's
/// `daemon/algod/api/server/v2/dependencies.go` CORS middleware.
static ENABLE_PRIVATE_NETWORK_ACCESS_HEADER: VersionedDefault<bool> =
    VersionedDefault::new(&[(35, || false)]);

/// Go: `RestConnectionsSoftLimit uint64` `version[20]:"1024"`
/// (`localTemplate.go:544`). Wired into the REST router as a
/// `tower::limit::ConcurrencyLimitLayer` bound: once in-flight requests
/// reach this count, further requests wait rather than being admitted
/// immediately (go's soft limit governs a similar admission-queue
/// backpressure point, not an outright rejection).
static REST_CONNECTIONS_SOFT_LIMIT: VersionedDefault<u64> = VersionedDefault::new(&[(20, || 1024)]);

/// Go: `RestConnectionsHardLimit uint64` `version[20]:"2048"`
/// (`localTemplate.go:547`). Wired into `ApiServer::serve`'s accept loop:
/// once concurrently-open connections reach this count, further accepted
/// sockets are closed immediately rather than handed to the router,
/// mirroring go's `limitlistener.RejectingLimitListener`.
static REST_CONNECTIONS_HARD_LIMIT: VersionedDefault<u64> = VersionedDefault::new(&[(20, || 2048)]);

/// Go: `MaxAPIResourcesPerAccount uint64` `version[21]:"100000"`
/// (`localTemplate.go:552`). Wired into `AlgodNodeInterface::
/// max_api_resources_per_account`, replacing the prior hardcoded
/// trait-default-only `100_000` (same value, now genuinely configurable).
static MAX_API_RESOURCES_PER_ACCOUNT: VersionedDefault<u64> =
    VersionedDefault::new(&[(21, || 100_000)]);

/// Go: `EnableUsageLog bool` `version[24]:"false"` (`localTemplate.go:573`).
/// **Documented no-op** (same pattern as `enable_ledger_service`):
/// algod-rust has no 10Hz CPU/RAM usage sampling/logging machinery to gate
/// yet. Round-trips through `config.json` for forward compatibility;
/// wiring is deferred to whichever follow-up issue adds that sampler.
static ENABLE_USAGE_LOG: VersionedDefault<bool> = VersionedDefault::new(&[(24, || false)]);

/// Go: `MaxAPIBoxPerApplication uint64` `version[25]:"100000"`
/// (`localTemplate.go:577`). Same "hardcoded → genuinely configurable"
/// fix as `max_api_resources_per_account`.
static MAX_API_BOX_PER_APPLICATION: VersionedDefault<u64> =
    VersionedDefault::new(&[(25, || 100_000)]);

/// Go: `TxIncomingFilteringFlags uint32` `version[26]:"1"`
/// (`localTemplate.go:584`). **Documented no-op**: algod-rust's gossip
/// transaction-message ingestion has no per-message-hash dedup filtering
/// stage to gate (only pool-level duplicate-transaction rejection exists
/// today). Round-trips through `config.json`; wiring is deferred to
/// whichever follow-up issue adds that filtering layer.
static TX_INCOMING_FILTERING_FLAGS: VersionedDefault<u32> = VersionedDefault::new(&[(26, || 1)]);

/// Go: `EnableExperimentalAPI bool` `version[26]:"false"`
/// (`localTemplate.go:588`). Was previously a hardcoded trait-default
/// `false` with no config wiring at all (unlike `EnableDeveloperAPI`, this
/// one wasn't even conflated with `dev_mode` — it was simply unwireable).
/// Now a genuine, independent config toggle.
static ENABLE_EXPERIMENTAL_API: VersionedDefault<bool> = VersionedDefault::new(&[(26, || false)]);

/// Go: `EnableFollowMode bool` `version[27]:"false"` (`localTemplate.go:598`).
/// **Architectural decision recorded here (issue #751)**: algod-rust keeps
/// its existing separate `algod-rust follow` CLI subcommand
/// (`bin/algod-rust/src/commands/follow.rs`, `cli.rs`'s `Commands::Follow`)
/// rather than unifying follower behavior into a mode flag on
/// `participate`. Investigated whether the two-entry-point split was a
/// deliberate divergence or an accreted implementation choice: found no
/// documented rationale either way, but concluded unification is *not*
/// clearly the right call — `follow` is a genuinely different runtime
/// shape (no agreement service, no participation keys, no pool, a
/// different network-attachment path entirely) built and tested as its own
/// binary entry point, and collapsing it into a `participate --follow`
/// flag would require threading "agreement service absent" through every
/// code path `participate::run` currently assumes has one, for no
/// behavioral gain — `algod-rust follow` already does everything
/// `EnableFollowMode` does. This field therefore round-trips through
/// `config.json` for forward/inspection compatibility only; it is a
/// documented no-op that does not gate any runtime behavior, and the
/// `Follow` subcommand remains the one way to run in follower mode.
static ENABLE_FOLLOW_MODE: VersionedDefault<bool> = VersionedDefault::new(&[(27, || false)]);

/// Go: `EnableTxnEvalTracer bool` `version[27]:"false"` (`localTemplate.go:602`,
/// gates `ledger.go:125`'s attachment of a `logic.EvalTracer` to the
/// *live* `BlockEvaluator`, exposing per-transaction trace data via algod
/// APIs for already-applied blocks). **Documented no-op**: algod-rust's
/// `EvalTracer` machinery (`algo_avm::tracer::EvalTracer`) exists and is
/// already wired for *simulate* (`Simulator::new_with_developer_api`,
/// gated by `EnableDeveloperAPI`), but there is no live block-apply trace
/// capture/API-exposure path to gate — `apply_transaction`'s
/// `Option<&mut dyn EvalTracer>` parameter is always `None` on the real
/// apply path today. Adding that capture/exposure machinery is new
/// functionality, out of scope for a config-knob issue; this field
/// round-trips through `config.json` for forward compatibility.
static ENABLE_TXN_EVAL_TRACER: VersionedDefault<bool> = VersionedDefault::new(&[(27, || false)]);

/// Go: `TxIncomingFilterMaxSize uint64` `version[28]:"500000"`
/// (`localTemplate.go:612`). Same documented-no-op scope as
/// `tx_incoming_filtering_flags` (only relevant once that filtering layer
/// exists).
static TX_INCOMING_FILTER_MAX_SIZE: VersionedDefault<u64> =
    VersionedDefault::new(&[(28, || 500_000)]);

/// Go: `EnableDeveloperAPI bool` `version[9]:"false"` (`localTemplate.go:435`).
/// **Fixes a real conflation bug** (issue #751): `AlgodNodeInterface::
/// enable_developer_api` previously returned `self.dev_mode` directly —
/// the *same* flag that also drives instant-block-production dev mode —
/// rather than reading an independent config value. go's
/// `EnableDeveloperAPI` is a standalone flag: a production relay/
/// participation node can enable the developer API without being in dev
/// mode, and vice versa. Now independently configurable (default `false`,
/// matching go), with `--dev`'s existing convenience behavior of enabling
/// the developer API preserved as an OR (`config value || dev_mode`) —
/// dev mode remains *a* way to turn it on, not the *only* way.
static ENABLE_DEVELOPER_API: VersionedDefault<bool> = VersionedDefault::new(&[(9, || false)]);

// --- Catchup/sync fields (issue #753) ---------------------------------------
//
// Scope decisions recorded here (see issue #753's PR description for the
// full write-up):
//
// - `CatchupParallelBlocks` is the one field in this group with a real
//   behavioral gap, not just missing config plumbing: the live node's
//   periodic catchup path (`algo_ledger::CatchupService::sync_pass`) fetched
//   blocks strictly serially before this issue, with no worker pool at all.
//   That gap is now closed (`CatchupService::start_with_parallelism`); this
//   field supplies the live value.
// - `TxSyncTimeoutSeconds`/`TxSyncIntervalSeconds`/`TxSyncServeResponseSize`
//   have a matching `algo_network::TxSyncerConfig` with the same defaults
//   already. `TxSyncer::start` itself is never invoked anywhere in the live
//   node binary today (only `TxSyncerConfig::default().seen_cache_size` is
//   read, to size an unrelated seen-tx cache) — a real, separate gap tracked
//   by its own follow-up issue rather than absorbed here. These fields still
//   round-trip through `config.json` and are threaded into the
//   `TxSyncerConfig` `participate` constructs at startup.
// - `EnableVerbosedTransactionSyncLogging`/`TransactionSyncDataExchangeRate`/
//   `TransactionSyncSignificantMessageThreshold` are **not applicable**:
//   investigated and confirmed dead in go-algorand v5.0.0-stable itself —
//   these fields exist only in `config/localTemplate.go`/`local_defaults.go`
//   with zero consumers anywhere in non-test Go source (no `txnsync`
//   package, no adaptive rate-based tx-sync protocol at this pin; that
//   experiment was retired upstream). Deliberately not added here.
// - The `TxBacklog*RateLimiting*`/congestion-manager group was originally a
//   9-field block judged entirely out of scope here (issue #753). Issue
//   #821 later found a genuine wiring point for the *app*-rate-limiter half
//   of that group — algod-rust's inbound gossip `TxTagHandler` (the
//   architectural analogue of go's `TxHandler.processIncomingTxn`, an
//   unsolicited peer-pushed ingestion path this repo didn't have when the
//   note below was first written) — so 5 of the 9 fields
//   (`TxBacklogServiceRateWindowSeconds`, `TxBacklogAppTxRateLimiterMaxSize`,
//   `TxBacklogAppTxPerSecondRate`, `TxBacklogAppRateLimitingCongestionPct`,
//   `EnableTxBacklogAppRateLimiting`) are now real config-plumbed knobs
//   feeding `algo_pool::AppRateLimiter` via `TxTagHandler::with_app_rate_limiter`
//   in `bin/algod-rust/src/commands/participate.rs`. See
//   `crates/core/algo-pool/src/app_rate_limiter.rs`'s module doc for the
//   full go-algorand trace establishing this as the only legitimate wiring
//   point (and why go's own pull-sync path, the analogue of algod-rust's
//   `tx_syncer.rs`, never applies this gate either).
//
//   The remaining 4 fields (`TxBacklogReservedCapacityPerPeer`,
//   `TxBacklogRateLimitingCongestionPct`, `EnableTxBacklogRateLimiting`,
//   `TxBacklogAppRateLimitingCountERLDrops`) gate go's *separate*
//   `ElasticRateLimiter`/RED congestion manager (`handler.erl`), whose
//   fairness property has its own redesigned pull-side analogue —
//   `algo_network::TxSyncPeerLimiter`, driven by its own
//   `TxSyncerConfig`/`TxSyncPeerLimiter::new` parameters, not these
//   `config.Local` fields (issue #860). Porting these 4 as additional
//   `config.json`-surfaced knobs for that already-wired mechanism remains a
//   judgment-called non-goal for now, same as `CatchpointDir`'s
//   hot/cold-directory-splitting group above — not silently dropped, just
//   not plumbed through `config.Local` yet.
// - `EnableAssembleStats`/`EnableProcessBlockStats`/`MaxBlockHistoryLookback`
//   are telemetry-event toggles / a lookback bound with no existing
//   algod-rust machinery to gate yet (no `AssembleBlockMetrics`/
//   `ProcessBlockMetrics` telemetry events, and the block DB always answers
//   transaction-ID lookback questions across its full retained history) —
//   **documented no-ops**, same pattern as `enable_ledger_service` above.
//   They round-trip through `config.json` for forward compatibility.

/// Go: `CatchupParallelBlocks uint64` `version[3]:"50" version[5]:"16"`
/// (`localTemplate.go:310-313`). Wired into
/// `CatchupService::start_with_parallelism` — see the module-level note
/// above for why this is the one field in this group with real behavioral
/// content, not just config plumbing.
static CATCHUP_PARALLEL_BLOCKS: VersionedDefault<u64> =
    VersionedDefault::new(&[(3, || 50), (5, || 16)]);

/// Go: `CatchupFailurePeerRefreshRate int` `version[0]:"10"`
/// (`localTemplate.go:207-208`). Config-field-only: algod-rust's periodic
/// catchup path does not track consecutive-failure counts per peer set to
/// replace yet (its retry/backoff is per-round, not peer-set-wide — see
/// `CatchupService::backoff_with_jitter`). Round-trips through
/// `config.json` for forward compatibility.
static CATCHUP_FAILURE_PEER_REFRESH_RATE: VersionedDefault<i64> =
    VersionedDefault::new(&[(0, || 10)]);

/// Go: `CatchupHTTPBlockFetchTimeoutSec int` `version[9]:"4"`
/// (`localTemplate.go:421-422`). Config-field-only: algod-rust's HTTP block
/// fetcher (`HttpBlockFetcher`, `algo-rest-client`) uses a fixed 30-second
/// client timeout rather than a per-relay-then-try-another-relay budget.
/// Round-trips through `config.json` for forward compatibility.
static CATCHUP_HTTP_BLOCK_FETCH_TIMEOUT_SEC: VersionedDefault<i64> =
    VersionedDefault::new(&[(9, || 4)]);

/// Go: `CatchupGossipBlockFetchTimeoutSec int` `version[9]:"4"`
/// (`localTemplate.go:424-425`). Config-field-only, same scope note as
/// `catchup_http_block_fetch_timeout_sec` (algod-rust's `GossipBlockFetcher`
/// already inherits a fixed 4-second per-peer timeout from
/// `GossipBlockSource`, matching this default's value but not yet
/// configurable).
static CATCHUP_GOSSIP_BLOCK_FETCH_TIMEOUT_SEC: VersionedDefault<i64> =
    VersionedDefault::new(&[(9, || 4)]);

/// Go: `CatchupLedgerDownloadRetryAttempts int` `version[9]:"50"`
/// (`localTemplate.go:427-428`). Config-field-only: algod-rust's
/// catchpoint-sync ledger download does not yet cap retries by an explicit
/// attempt count. Round-trips through `config.json` for forward
/// compatibility.
static CATCHUP_LEDGER_DOWNLOAD_RETRY_ATTEMPTS: VersionedDefault<i64> =
    VersionedDefault::new(&[(9, || 50)]);

/// Go: `CatchupBlockDownloadRetryAttempts int` `version[9]:"1000"`
/// (`localTemplate.go:430-431`). Config-field-only, same scope note as
/// `catchup_ledger_download_retry_attempts`.
static CATCHUP_BLOCK_DOWNLOAD_RETRY_ATTEMPTS: VersionedDefault<i64> =
    VersionedDefault::new(&[(9, || 1_000)]);

/// Go: `TxSyncTimeoutSeconds int64` `version[0]:"30"` (`localTemplate.go:277`).
/// Wired into `algo_network::TxSyncerConfig::sync_timeout` — see the
/// module-level note above on `TxSyncer::start` not being invoked from the
/// live node yet.
static TX_SYNC_TIMEOUT_SECONDS: VersionedDefault<i64> = VersionedDefault::new(&[(0, || 30)]);

/// Go: `TxSyncIntervalSeconds int64` `version[0]:"60"` (`localTemplate.go:280`).
/// See `tx_sync_timeout_seconds`'s note.
static TX_SYNC_INTERVAL_SECONDS: VersionedDefault<i64> = VersionedDefault::new(&[(0, || 60)]);

/// Go: `TxSyncServeResponseSize int` `version[3]:"1000000"`
/// (`localTemplate.go:324-325`). See `tx_sync_timeout_seconds`'s note.
static TX_SYNC_SERVE_RESPONSE_SIZE: VersionedDefault<i64> =
    VersionedDefault::new(&[(3, || 1_000_000)]);

/// Go: `TxBacklogServiceRateWindowSeconds int` `version[27]:"10"`
/// (`localTemplate.go:237-238`). Wired into
/// `algo_pool::AppRateLimiter::new`'s `service_rate_window` argument in
/// `bin/algod-rust/src/commands/participate.rs` (issue #821) — the
/// sliding-window duration over which `TxBacklogAppTxPerSecondRate` is
/// enforced.
static TX_BACKLOG_SERVICE_RATE_WINDOW_SECONDS: VersionedDefault<i64> =
    VersionedDefault::new(&[(27, || 10)]);

/// Go: `TxBacklogAppTxRateLimiterMaxSize int` `version[32]:"1048576"`
/// (`localTemplate.go:243-245`). Wired into
/// `algo_pool::AppRateLimiter::new`'s `max_cache_size` argument (issue
/// #821).
static TX_BACKLOG_APP_TX_RATE_LIMITER_MAX_SIZE: VersionedDefault<i64> =
    VersionedDefault::new(&[(32, || 1_048_576)]);

/// Go: `TxBacklogAppTxPerSecondRate int` `version[32]:"100"`
/// (`localTemplate.go:247-248`). Wired into
/// `algo_pool::AppRateLimiter::new`'s `max_app_peer_rate` argument (issue
/// #821).
static TX_BACKLOG_APP_TX_PER_SECOND_RATE: VersionedDefault<i64> =
    VersionedDefault::new(&[(32, || 100)]);

/// Go: `TxBacklogAppRateLimitingCongestionPct int` `version[38]:"10"`
/// (`localTemplate.go:253-254`). Wired into
/// `TxTagHandler::with_app_rate_limiter`'s `congestion_threshold` argument
/// (issue #821): `pool_size * this_pct / 100` pending transactions is the
/// threshold above which the app-rate-limit admission check engages.
static TX_BACKLOG_APP_RATE_LIMITING_CONGESTION_PCT: VersionedDefault<i64> =
    VersionedDefault::new(&[(38, || 10)]);

/// Go: `EnableTxBacklogAppRateLimiting bool` `version[32]:"true"`
/// (`localTemplate.go:256-257`). Wired into whether
/// `bin/algod-rust/src/commands/participate.rs` attaches an
/// `AppRateLimiter` to its `TxTagHandler`s at all (issue #821).
static ENABLE_TX_BACKLOG_APP_RATE_LIMITING: VersionedDefault<bool> =
    VersionedDefault::new(&[(32, || true)]);

/// Go: `EnableAssembleStats bool` `version[0]:""` (`localTemplate.go:315-316`).
/// **Documented no-op** — see the module-level note above.
static ENABLE_ASSEMBLE_STATS: VersionedDefault<bool> = VersionedDefault::new(&[(0, || false)]);

/// Go: `EnableProcessBlockStats bool` `version[0]:""` (`localTemplate.go:318-319`).
/// **Documented no-op** — see the module-level note above.
static ENABLE_PROCESS_BLOCK_STATS: VersionedDefault<bool> = VersionedDefault::new(&[(0, || false)]);

/// Go: `MaxBlockHistoryLookback uint64` `version[31]:"0"` (`localTemplate.go:568-569`).
/// **Documented no-op** — see the module-level note above.
static MAX_BLOCK_HISTORY_LOOKBACK: VersionedDefault<u64> = VersionedDefault::new(&[(31, || 0)]);

// --- Agreement-protocol fields (issue #755) ---------------------------------
//
// Scope decisions recorded here (see issue #755's PR description for the
// full write-up):
//
// - `AgreementIncomingVotesQueueLength`/`...ProposalsQueueLength`/
//   `...BundlesQueueLength` are wired into
//   `algo_network::AgreementNetworkConfig` (`vote_queue_len`/
//   `proposal_queue_len`/`bundle_queue_len`), which sizes the bounded
//   channels `AgreementNetworkBridge` uses to buffer incoming gossip
//   messages by tag. This also **fixes a real stale-default bug**: the
//   proposal/bundle constants in `algo-network` were still go's pre-v27
//   values (25/7) even though go bumped both at version 27 (to 50/15) --
//   see `crates/node/algo-network/src/agreement_network.rs`'s
//   `DEFAULT_PROPOSAL_QUEUE_LEN`/`DEFAULT_BUNDLE_QUEUE_LEN`.
// - `MaxAcctLookback` is wired into `SqliteLedger::set_delta_cache_window`
//   as a *floor* on top of `crate::delta_cache::DEFAULT_WINDOW_SIZE` (320
//   rounds), never below it. An earlier version of this change set
//   `DEFAULT_WINDOW_SIZE` itself to go's literal default of 4
//   (`ledger/acctupdates.go:294`), reasoning that 320 -- 80x go's default
//   -- had no algod-rust architectural justification (the *unrelated*
//   balance/seed-lookback constant that happens to also equal 320,
//   `BALANCE_LOOKBACK` in `algo-ledger/src/apply.rs`, governs online
//   participation/stake accounting, not delta-cache retention). **CI's
//   live dual-node parity suite caught a real regression from that**:
//   go's `MaxAcctLookback` is documented as a *minimum* beneath a
//   lazily-batched commit process (`ledger/acctupdates.go:224`,
//   `accountUpdates.produceCommittingTask`), so go's real retained depth
//   is routinely much larger than 4 in practice; algod-rust's `DeltaCache`
//   has no equivalent lazy-commit-lag mechanism and is a hard ceiling, so
//   matching go's literal minimum evicted deltas go itself still served.
//   Reverted `DEFAULT_WINDOW_SIZE` to 320 and instead apply this field as
//   a floor (`window_size.max(DEFAULT_WINDOW_SIZE)`), faithful to go's own
//   "minimum" framing without algod-rust's differently-shaped cache
//   inheriting go's differently-shaped safety margin. See
//   `algo_ledger::delta_cache::DEFAULT_WINDOW_SIZE`'s doc comment for the
//   full writeup.
// - `EnableAgreementReporting`/`EnableAgreementTimeMetrics` are wired into
//   `algo_agreement::Tracer::new` via `Service::with_tracer`, constructed
//   from these two config bools at agreement-service startup
//   (`bin/algod-rust/src/commands/participate.rs`). The tracer's
//   `log_event_in`/`log_actions` calls are invoked from
//   `RootRouter::submit_top` (mirroring go's `rootRouter.submitTop`
//   calling `t.ainTop`/`t.aoutTop` at the same dispatch point,
//   `agreement/router.go:175-188`) -- a single, low-risk call site rather
//   than threading a tracer parameter through every internal dispatch
//   function in the state-machine tree.

/// Go: `AgreementIncomingVotesQueueLength uint64` `version[21]:"10000"
/// version[27]:"20000"` (`localTemplate.go:554-555`). Wired into
/// `algo_network::AgreementNetworkConfig::vote_queue_len`.
static AGREEMENT_INCOMING_VOTES_QUEUE_LENGTH: VersionedDefault<u64> =
    VersionedDefault::new(&[(21, || 10_000), (27, || 20_000)]);

/// Go: `AgreementIncomingProposalsQueueLength uint64` `version[21]:"25"
/// version[27]:"50"` (`localTemplate.go:557-558`). Wired into
/// `algo_network::AgreementNetworkConfig::proposal_queue_len`. See the
/// module-level note above -- algod-rust's own constant for this was stale
/// at the pre-v27 value before this issue.
static AGREEMENT_INCOMING_PROPOSALS_QUEUE_LENGTH: VersionedDefault<u64> =
    VersionedDefault::new(&[(21, || 25), (27, || 50)]);

/// Go: `AgreementIncomingBundlesQueueLength uint64` `version[21]:"7"
/// version[27]:"15"` (`localTemplate.go:560-561`). Wired into
/// `algo_network::AgreementNetworkConfig::bundle_queue_len`. See the
/// module-level note above -- algod-rust's own constant for this was stale
/// at the pre-v27 value before this issue.
static AGREEMENT_INCOMING_BUNDLES_QUEUE_LENGTH: VersionedDefault<u64> =
    VersionedDefault::new(&[(21, || 7), (27, || 15)]);

/// Go: `MaxAcctLookback uint64` `version[23]:"4"` (`localTemplate.go:563-565`).
/// Wired into `SqliteLedger::set_delta_cache_window` as a floor, not a
/// ceiling -- see the module-level note above.
static MAX_ACCT_LOOKBACK: VersionedDefault<u64> = VersionedDefault::new(&[(23, || 4)]);

/// Go: `EnableAgreementReporting bool` `version[3]:"false"`
/// (`localTemplate.go:219-220`). Wired into `Tracer::new`'s first argument
/// via `Service::with_tracer` -- see the module-level note above.
static ENABLE_AGREEMENT_REPORTING: VersionedDefault<bool> = VersionedDefault::new(&[(3, || false)]);

/// Go: `EnableAgreementTimeMetrics bool` `version[3]:"false"`
/// (`localTemplate.go:222-223`). Wired into `Tracer::new`'s second argument
/// via `Service::with_tracer` -- see the module-level note above.
static ENABLE_AGREEMENT_TIME_METRICS: VersionedDefault<bool> =
    VersionedDefault::new(&[(3, || false)]);

// --- Logging / telemetry / profiling fields (issue #756) --------------------
//
// See issue #756's disposition write-up (also `docs/PHASE16_PROPOSAL.md`'s
// "Remote telemetry-reporting is a deliberate non-goal" section) for the
// full reasoning. Two categories below:
//
// 1. Fields that round-trip through `config.json` with a real (if
//    currently no-op) meaning, added here: `TelemetryToLog`,
//    `BaseLoggerDebugLevel`, `CadaverSizeTarget`/`CadaverDirectory`,
//    `LogSizeLimit`/`LogArchiveName`/`LogArchiveMaxAge`, `EnableProfiler`,
//    `EnableTopAccountsReporting`.
// 2. Fields deliberately NOT added at all: `PeerConnectionsUpdateInterval`,
//    `HeartbeatUpdateInterval`, `EnableAccountUpdatesStats`,
//    `AccountUpdatesStatsInterval`. Each one's *only* upstream effect is
//    feeding the remote-telemetry-reporting pipeline this issue declines to
//    build (`network/wsNetwork.go`'s `sendPeerConnectionsTelemetryStatus`
//    checks `log.GetTelemetryEnabled()` and returns immediately when
//    telemetry is off; `cmd/algod/main.go`'s heartbeat goroutine calls
//    `log.EventWithDetails`; `ledger/acctupdates.go:2291` calls
//    `au.log.Metrics(telemetryspec.Accounts, ...)` — all three are
//    telemetry-event emission, gated on a telemetry subsystem algod-rust
//    doesn't have). Since algod-rust has no telemetry client for these
//    intervals to govern, adding them as inert round-trip fields would
//    misrepresent them as "will matter once you set them" — unlike the
//    fields above (which have *some* independent local meaning: log
//    verbosity, cadaver file rotation, etc.), these four have none. Same
//    disposition pattern as the networking fields already excluded in the
//    module docs above (message-hash-bucket dedup filtering, etc.).

/// Go: `TelemetryToLog bool` `version[5]:"true"` (`localTemplate.go:374-375`).
/// **Documented no-op**: controls whether telemetry-tagged log lines are
/// *also* mirrored into local `node.log` — distinct from (and independent
/// of) the remote-telemetry-reporting client itself, which is a deliberate
/// non-goal (see module note above). algod-rust's tracing output has no
/// concept of a "telemetry-tagged" log line to mirror, since there is no
/// telemetry event-emission subsystem producing them. Round-trips through
/// `config.json` for forward compatibility; would gain real meaning only if
/// a future issue adds telemetry-tagged tracing events independent of the
/// remote-reporting client.
static TELEMETRY_TO_LOG: VersionedDefault<bool> = VersionedDefault::new(&[(5, || true)]);

/// Go: `BaseLoggerDebugLevel uint32` `version[0]:"1" version[1]:"4"`
/// (`localTemplate.go:79-80`). go's `logging.Level`: 0=Panic, 1=Fatal,
/// 2=Error, 3=Warn, 4=Info, 5=Debug. [`base_logger_debug_level_to_filter_directive`]
/// converts this into a `tracing_subscriber::EnvFilter` directive string.
/// **Not wired into the CLI's global subscriber**: `bin/algod-rust/src/
/// main.rs` initializes the process-wide tracing subscriber (from
/// `RUST_LOG`, defaulting to `"info"`) before any subcommand parses its
/// `--data-dir` and loads that directory's `config.json` — restructuring
/// every subcommand's startup order to load config before installing the
/// logger is a cross-cutting change out of scope for this config-audit
/// issue. The conversion helper exists so that restructuring, whenever it
/// happens, has a ready-made and independently tested go-level -> directive
/// mapping to call.
static BASE_LOGGER_DEBUG_LEVEL: VersionedDefault<u32> =
    VersionedDefault::new(&[(0, || 1), (1, || 4)]);

/// Go: `CadaverSizeTarget uint64` `version[0]:"1073741824" version[24]:"0"`
/// (`localTemplate.go:82-83`). `0` disables cadaver tracing entirely (go's
/// `agreement/trace.go:84-85` `makeTracer`'s `fileSizeTarget == 0` branch).
/// [`crate::trace`] --- see `algo_agreement::trace::resolve_cadaver_config`
/// for the real conversion into a [`CadaverConfig`]-shaped writer
/// configuration (that function lives in `algo-agreement` since
/// [`CadaverConfig`] is defined there, not in this crate).
///
/// [`CadaverConfig`]: https://docs.rs/algo-agreement (see
/// `algo_agreement::trace::CadaverConfig`)
static CADAVER_SIZE_TARGET: VersionedDefault<u64> =
    VersionedDefault::new(&[(0, || 1_073_741_824), (24, || 0)]);

/// Go: `CadaverDirectory string` `version[27]:""` (`localTemplate.go:86`).
/// Empty string means "use the fallback directory" — go falls back to
/// `ColdDataDir` (`agreement/service.go:111-114`), which algod-rust doesn't
/// have (see [`CATCHPOINT_DIR`]'s doc comment for that architectural
/// non-goal); the caller-supplied default directory in
/// `resolve_cadaver_config` stands in for it instead.
static CADAVER_DIRECTORY: VersionedDefault<String> =
    VersionedDefault::new(&[(27, || String::new())]);

/// Go: `LogSizeLimit uint64` `version[0]:"1073741824"` (`localTemplate.go:190-191`).
/// **Documented no-op**: algod-rust's process logging always writes to
/// stdout via `tracing_subscriber` (`bin/algod-rust/src/main.rs`) — there is
/// no file-based `node.log` writer to size-limit or rotate. Round-trips
/// through `config.json` for forward compatibility; would gain real meaning
/// only if a future issue adds a file-backed rotating log writer (go itself
/// treats `0` as "write to stdout instead", so a from-scratch writer would
/// need to replicate that same escape hatch).
static LOG_SIZE_LIMIT: VersionedDefault<u64> = VersionedDefault::new(&[(0, || 1_073_741_824)]);

/// Go: `LogArchiveName string` `version[4]:"node.archive.log"`
/// (`localTemplate.go:193-201`). Same documented-no-op scope as
/// `log_size_limit` — the archive filename template has nothing to name
/// without a rotating file-backed log writer.
static LOG_ARCHIVE_NAME: VersionedDefault<String> =
    VersionedDefault::new(&[(4, || "node.archive.log".to_string())]);

/// Go: `LogArchiveMaxAge string` `version[4]:""` (`localTemplate.go:203-205`).
/// Same documented-no-op scope as `log_size_limit`.
static LOG_ARCHIVE_MAX_AGE: VersionedDefault<String> =
    VersionedDefault::new(&[(4, || String::new())]);

/// Go: `EnableProfiler bool` `version[0]:"false"` (`localTemplate.go:364-366`).
/// Gates go's `net/http/pprof` debug endpoints
/// (`daemon/algod/api/server/router.go:126`, `daemon/algod/server.go:26`) —
/// distinct from the always-available `/debug/settings/pprof` mutex/block
/// sample-rate admin endpoint algod-rust already has
/// (`crates/node/algo-rest-api/src/handlers.rs::get_debug_settings_prof`,
/// unconditional in both implementations). **Documented no-op**: algod-rust
/// has no equivalent embedded CPU/heap-profiling HTTP endpoint to gate —
/// Rust's profiling conventions favor external tooling (`perf`,
/// `cargo flamegraph`, `tokio-console`) over an in-process pprof server, so
/// building one is a from-scratch feature, not a config-gating fix, and is
/// out of scope for this config-audit issue. Round-trips through
/// `config.json` for forward compatibility.
static ENABLE_PROFILER: VersionedDefault<bool> = VersionedDefault::new(&[(0, || false)]);

/// Go: `EnableTopAccountsReporting bool` `version[0]:"false"`
/// (`localTemplate.go:216-217`). go's own doc comment: "Deprecated, do not
/// use." **Documented not-applicable**, matching upstream's own
/// deprecation — round-trips through `config.json` for forward
/// compatibility (an operator's existing file may still carry this key),
/// but is never read for any behavior.
static ENABLE_TOP_ACCOUNTS_REPORTING: VersionedDefault<bool> =
    VersionedDefault::new(&[(0, || false)]);

// --- Metrics fields (issue #776, follow-up to #756) -------------------------
//
// #756's investigation found algod-rust's `/metrics` Prometheus registry had
// zero runtime- or netdev-style counters to gate, so it split these two
// fields off rather than build brand-new metrics infrastructure inside a
// config-audit issue. This issue adds that infrastructure
// (`algo_rest_api::process_metrics`) and wires both flags to it for real —
// see that module's doc comment for the Go-runtime -> Rust mapping decision.

/// Go: `EnableRuntimeMetrics bool` `version[22]:"false"` (`localTemplate.go:368-369`).
/// Introduced by go-algorand commit `c516ac37e` ("metrics: collect and report
/// Go runtime.metrics (#4041)"). Gates `daemon/algod/server.go:338-340`'s
/// registration of `metrics.NewRuntimeMetrics()` into the process-wide
/// Prometheus registry. Wired into
/// `AlgodNodeInterface::metrics_exposition` — see
/// `algo_rest_api::process_metrics::RuntimeMetricsSnapshot`.
static ENABLE_RUNTIME_METRICS: VersionedDefault<bool> = VersionedDefault::new(&[(22, || false)]);

/// Go: `EnableNetDevMetrics bool` `version[34]:"false"` (`localTemplate.go:371-372`).
/// Introduced by go-algorand commit `e14fea6b3` ("metrics: collect total
/// netdev sent/received bytes (#6108)"). Gates
/// `daemon/algod/server.go:342-344`'s registration of `metrics.NetDevMetrics`
/// into the process-wide Prometheus registry. Wired into
/// `AlgodNodeInterface::metrics_exposition` — see
/// `algo_rest_api::process_metrics::NetDevMetricsSnapshot`.
static ENABLE_NET_DEV_METRICS: VersionedDefault<bool> = VersionedDefault::new(&[(34, || false)]);

// --- Remaining networking fields (issue #768, follow-up to #748) -----------
//
// #748 scoped down `config.Local`'s full networking-field enumeration to
// what could be wired with real behavioral impact in one PR. This issue
// closes the rest of the enumerated gap. Per-field disposition (see issue
// #768's body for the full table):
//
// - `public_address`/`p2p_hybrid_net_address`: round-trip only. Go gates
//   `P2PHybridNetAddress`-driven hybrid-mode validation
//   (`ValidateP2PHybridConfig`, `localTemplate.go:800-812`) on
//   `PublicAddress` being set; algod-rust has no hybrid-mode
//   listen-address validation path to gate yet (`enable_p2p_hybrid_mode`
//   is itself a round-trip-only field already — see its doc comment).
// - `announce_participation_key`/`reserved_fds`: round-trip only, no
//   underlying announcement/FD-accounting subsystem exists.
// - `priority_peers`: round-trip only (no per-IP peer-priority scheduling
//   in the phonebook/mesh yet), but demonstrates the non-`Copy`
//   `VersionedDefault<BTreeMap<String, bool>>` shape end-to-end.
// - The four message-filter fields plus `enable_outgoing_network_message_filtering`/
//   `enable_incoming_message_filter`: wired into `algo_network`'s existing
//   `MessageFilter` bucket construction (`message_filter.rs`), which
//   previously hardcoded a single bucket-size constant with no
//   bucket-count knob and no incoming/outgoing split at all.
// - `dns_security_flags`/`network_protocol_version`/
//   `use_x_forwarded_for_address_field`/`disable_outgoing_connection_throttling`/
//   `block_service_custom_fallback_endpoints`/`enable_request_logger`/
//   `fallback_dns_resolver_address`: round-trip only, no underlying
//   DNS-response-validation, protocol-version-override,
//   X-Forwarded-For-aware client-IP resolution, outgoing-throttle-disable,
//   custom-fallback-endpoint, request-logging, or fallback-DNS-resolver
//   subsystem exists to gate.
// - `disable_localhost_connection_rate_limit`: wired into the inbound
//   connection-rate limiter (`algo_network::ConnectionTracker`) as a
//   real behavioral fix — localhost connections previously got no
//   exemption from the same per-IP rate limiter as everything else.
// - `p2p_private_key_location`: wired as a custom-path override alongside
//   the existing `--p2p-persist-peer-id` boolean flag.
// - `enable_dht_providers`/`dht_mode`: wired into `algo_p2p::dht`'s
//   existing (previously config-less) DHT construction.
// - `EnableVoteCompression`/`StatefulVoteCompressionTableSize`/
//   `EnableBatchVerification` are **deliberately NOT added** here, per
//   issue #768's explicit instruction: confirmed no vote-compression code
//   exists anywhere in algod-rust's gossip wire protocol, and
//   `algo_validate::signature` itself documents "no ed25519 batch
//   verifier" today — a no-op knob for a nonexistent feature is worse
//   than no knob (same precedent #748 set). Add them only once a future
//   issue actually builds the underlying feature.

/// Go: `PublicAddress string` `version[0]:""` (`localTemplate.go:65`).
/// Round-trip only — see the module note above.
static PUBLIC_ADDRESS: VersionedDefault<String> = VersionedDefault::new(&[(0, String::new)]);

/// Go: `P2PHybridNetAddress string` `version[34]:""` (`localTemplate.go:627`).
/// Round-trip only — see the module note above.
static P2P_HYBRID_NET_ADDRESS: VersionedDefault<String> =
    VersionedDefault::new(&[(34, String::new)]);

/// Go: `AnnounceParticipationKey bool` `version[4]:"true"`
/// (`localTemplate.go:155`). Round-trip only — see the module note above.
static ANNOUNCE_PARTICIPATION_KEY: VersionedDefault<bool> = VersionedDefault::new(&[(4, || true)]);

/// Go: `PriorityPeers map[string]bool` `version[4]:""` (`localTemplate.go:159`).
/// Round-trip only — demonstrates the non-`Copy`
/// `VersionedDefault<BTreeMap<String, bool>>` shape (`T` only needs
/// `Default`, not `Copy` — see [`VersionedDefault::at`]'s doc comment).
static PRIORITY_PEERS: VersionedDefault<BTreeMap<String, bool>> =
    VersionedDefault::new(&[(4, BTreeMap::new)]);

/// Go: `ReservedFDs uint64` `version[2]:"256"` (`localTemplate.go:167`).
/// Round-trip only — see the module note above.
static RESERVED_FDS: VersionedDefault<u64> = VersionedDefault::new(&[(2, || 256)]);

/// Go: `IncomingMessageFilterBucketCount int` `version[0]:"5"`
/// (`localTemplate.go:283`). Wired into `algo_network`'s incoming
/// `MessageFilter` bucket construction.
static INCOMING_MESSAGE_FILTER_BUCKET_COUNT: VersionedDefault<i64> =
    VersionedDefault::new(&[(0, || 5)]);

/// Go: `IncomingMessageFilterBucketSize int` `version[0]:"512"`
/// (`localTemplate.go:286`). Wired into `algo_network`'s incoming
/// `MessageFilter` bucket construction — algod-rust's prior hardcoded
/// bucket capacity (`MESSAGE_FILTER_SIZE`, 5000) was actually go's
/// unrelated `messageFilterSize` large-message-notification threshold,
/// not a bucket-size default at all; this field supplies the real one.
static INCOMING_MESSAGE_FILTER_BUCKET_SIZE: VersionedDefault<i64> =
    VersionedDefault::new(&[(0, || 512)]);

/// Go: `OutgoingMessageFilterBucketCount int` `version[0]:"3"`
/// (`localTemplate.go:289`). Wired into `algo_network`'s outgoing
/// `MessageFilter` bucket construction.
static OUTGOING_MESSAGE_FILTER_BUCKET_COUNT: VersionedDefault<i64> =
    VersionedDefault::new(&[(0, || 3)]);

/// Go: `OutgoingMessageFilterBucketSize int` `version[0]:"128"`
/// (`localTemplate.go:292`). Wired into `algo_network`'s outgoing
/// `MessageFilter` bucket construction.
static OUTGOING_MESSAGE_FILTER_BUCKET_SIZE: VersionedDefault<i64> =
    VersionedDefault::new(&[(0, || 128)]);

/// Go: `EnableOutgoingNetworkMessageFiltering bool` `version[0]:"true"`
/// (`localTemplate.go:295`). Wired: gates whether an outgoing
/// `MessageFilter` is constructed at all.
static ENABLE_OUTGOING_NETWORK_MESSAGE_FILTERING: VersionedDefault<bool> =
    VersionedDefault::new(&[(0, || true)]);

/// Go: `EnableIncomingMessageFilter bool` `version[0]:"false"`
/// (`localTemplate.go:298`). Wired: gates whether an incoming
/// `MessageFilter` is constructed at all.
static ENABLE_INCOMING_MESSAGE_FILTER: VersionedDefault<bool> =
    VersionedDefault::new(&[(0, || false)]);

/// Go: `DNSSecurityFlags uint32` `version[6]:"1" version[34]:"9"`
/// (`localTemplate.go:385`). Round-trip only — see the module note above.
static DNS_SECURITY_FLAGS: VersionedDefault<u32> = VersionedDefault::new(&[(6, || 1), (34, || 9)]);

/// Go: `NetworkProtocolVersion string` `version[6]:""` (`localTemplate.go:395`).
/// Round-trip only — see the module note above.
static NETWORK_PROTOCOL_VERSION: VersionedDefault<String> =
    VersionedDefault::new(&[(6, String::new)]);

/// Go: `UseXForwardedForAddressField string` `version[0]:""`
/// (`localTemplate.go:337`). Round-trip only — see the module note above.
static USE_X_FORWARDED_FOR_ADDRESS_FIELD: VersionedDefault<String> =
    VersionedDefault::new(&[(0, String::new)]);

/// Go: `DisableOutgoingConnectionThrottling bool` `version[5]:"false"`
/// (`localTemplate.go:392`). Round-trip only — see the module note above.
static DISABLE_OUTGOING_CONNECTION_THROTTLING: VersionedDefault<bool> =
    VersionedDefault::new(&[(5, || false)]);

/// Go: `DisableLocalhostConnectionRateLimit bool` `version[16]:"true"`
/// (`localTemplate.go:481`). Wired into `algo_network::ConnectionTracker`:
/// when `true` (go's real default), loopback addresses are exempted from
/// the inbound per-IP connection-rate limiter.
static DISABLE_LOCALHOST_CONNECTION_RATE_LIMIT: VersionedDefault<bool> =
    VersionedDefault::new(&[(16, || true)]);

/// Go: `BlockServiceCustomFallbackEndpoints string` `version[16]:""`
/// (`localTemplate.go:486`). Round-trip only — see the module note above.
static BLOCK_SERVICE_CUSTOM_FALLBACK_ENDPOINTS: VersionedDefault<String> =
    VersionedDefault::new(&[(16, String::new)]);

/// Go: `EnableRequestLogger bool` `version[4]:"false"` (`localTemplate.go:354`).
/// Round-trip only — see the module note above.
static ENABLE_REQUEST_LOGGER: VersionedDefault<bool> = VersionedDefault::new(&[(4, || false)]);

/// Go: `FallbackDNSResolverAddress string` `version[0]:""`
/// (`localTemplate.go:229`). Round-trip only — see the module note above.
static FALLBACK_DNS_RESOLVER_ADDRESS: VersionedDefault<String> =
    VersionedDefault::new(&[(0, String::new)]);

/// Go: `P2PPrivateKeyLocation string` `version[29]:""`
/// (`localTemplate.go:647`). Wired as a custom-path override for the
/// P2P peer-ID private key file, alongside the existing
/// `p2p_persist_peer_id` boolean flag.
static P2P_PRIVATE_KEY_LOCATION: VersionedDefault<String> =
    VersionedDefault::new(&[(29, String::new)]);

/// Go: `EnableDHTProviders bool` `version[34]:"false"` (`localTemplate.go:630`).
/// Wired into `algo_p2p::dht`'s DHT construction.
static ENABLE_DHT_PROVIDERS: VersionedDefault<bool> = VersionedDefault::new(&[(34, || false)]);

/// Go: `DHTMode string` `version[38]:""` (`localTemplate.go:638`).
/// Wired into `algo_p2p::dht`'s DHT construction.
static DHT_MODE: VersionedDefault<String> = VersionedDefault::new(&[(38, String::new)]);

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
fn default_catchpoint_dir() -> String {
    CATCHPOINT_DIR.at(LATEST_VERSION)
}
fn default_stateproof_dir() -> String {
    STATEPROOF_DIR.at(LATEST_VERSION)
}
fn default_hot_data_dir() -> String {
    HOT_DATA_DIR.at(LATEST_VERSION)
}
fn default_cold_data_dir() -> String {
    COLD_DATA_DIR.at(LATEST_VERSION)
}
fn default_tracker_db_dir() -> String {
    TRACKER_DB_DIR.at(LATEST_VERSION)
}
fn default_block_db_dir() -> String {
    BLOCK_DB_DIR.at(LATEST_VERSION)
}
fn default_crash_db_dir() -> String {
    CRASH_DB_DIR.at(LATEST_VERSION)
}
fn default_log_file_dir() -> String {
    LOG_FILE_DIR.at(LATEST_VERSION)
}
fn default_log_archive_dir() -> String {
    LOG_ARCHIVE_DIR.at(LATEST_VERSION)
}
fn default_catchpoint_interval() -> u64 {
    CATCHPOINT_INTERVAL.at(LATEST_VERSION)
}
fn default_catchpoint_file_history_length() -> i64 {
    CATCHPOINT_FILE_HISTORY_LENGTH.at(LATEST_VERSION)
}
fn default_catchpoint_tracking() -> i64 {
    CATCHPOINT_TRACKING.at(LATEST_VERSION)
}
fn default_archival() -> bool {
    ARCHIVAL.at(LATEST_VERSION)
}
fn default_optimize_accounts_database_on_startup() -> bool {
    OPTIMIZE_ACCOUNTS_DATABASE_ON_STARTUP.at(LATEST_VERSION)
}
fn default_ledger_synchronous_mode() -> i64 {
    LEDGER_SYNCHRONOUS_MODE.at(LATEST_VERSION)
}
fn default_accounts_rebuild_synchronous_mode() -> i64 {
    ACCOUNTS_REBUILD_SYNCHRONOUS_MODE.at(LATEST_VERSION)
}
fn default_max_catchpoint_download_duration() -> i64 {
    MAX_CATCHPOINT_DOWNLOAD_DURATION.at(LATEST_VERSION)
}
fn default_min_catchpoint_file_download_bytes_per_second() -> u64 {
    MIN_CATCHPOINT_FILE_DOWNLOAD_BYTES_PER_SECOND.at(LATEST_VERSION)
}
fn default_disable_ledger_lru_cache() -> bool {
    DISABLE_LEDGER_LRU_CACHE.at(LATEST_VERSION)
}
fn default_endpoint_address() -> String {
    ENDPOINT_ADDRESS.at(LATEST_VERSION)
}
fn default_rest_read_timeout_seconds() -> i64 {
    REST_READ_TIMEOUT_SECONDS.at(LATEST_VERSION)
}
fn default_rest_write_timeout_seconds() -> i64 {
    REST_WRITE_TIMEOUT_SECONDS.at(LATEST_VERSION)
}
fn default_enable_private_network_access_header() -> bool {
    ENABLE_PRIVATE_NETWORK_ACCESS_HEADER.at(LATEST_VERSION)
}
fn default_rest_connections_soft_limit() -> u64 {
    REST_CONNECTIONS_SOFT_LIMIT.at(LATEST_VERSION)
}
fn default_rest_connections_hard_limit() -> u64 {
    REST_CONNECTIONS_HARD_LIMIT.at(LATEST_VERSION)
}
fn default_max_api_resources_per_account() -> u64 {
    MAX_API_RESOURCES_PER_ACCOUNT.at(LATEST_VERSION)
}
fn default_enable_usage_log() -> bool {
    ENABLE_USAGE_LOG.at(LATEST_VERSION)
}
fn default_max_api_box_per_application() -> u64 {
    MAX_API_BOX_PER_APPLICATION.at(LATEST_VERSION)
}
fn default_tx_incoming_filtering_flags() -> u32 {
    TX_INCOMING_FILTERING_FLAGS.at(LATEST_VERSION)
}
fn default_enable_experimental_api() -> bool {
    ENABLE_EXPERIMENTAL_API.at(LATEST_VERSION)
}
fn default_enable_follow_mode() -> bool {
    ENABLE_FOLLOW_MODE.at(LATEST_VERSION)
}
fn default_enable_txn_eval_tracer() -> bool {
    ENABLE_TXN_EVAL_TRACER.at(LATEST_VERSION)
}
fn default_tx_incoming_filter_max_size() -> u64 {
    TX_INCOMING_FILTER_MAX_SIZE.at(LATEST_VERSION)
}
fn default_enable_developer_api() -> bool {
    ENABLE_DEVELOPER_API.at(LATEST_VERSION)
}
fn default_catchup_parallel_blocks() -> u64 {
    CATCHUP_PARALLEL_BLOCKS.at(LATEST_VERSION)
}
fn default_catchup_failure_peer_refresh_rate() -> i64 {
    CATCHUP_FAILURE_PEER_REFRESH_RATE.at(LATEST_VERSION)
}
fn default_catchup_http_block_fetch_timeout_sec() -> i64 {
    CATCHUP_HTTP_BLOCK_FETCH_TIMEOUT_SEC.at(LATEST_VERSION)
}
fn default_catchup_gossip_block_fetch_timeout_sec() -> i64 {
    CATCHUP_GOSSIP_BLOCK_FETCH_TIMEOUT_SEC.at(LATEST_VERSION)
}
fn default_catchup_ledger_download_retry_attempts() -> i64 {
    CATCHUP_LEDGER_DOWNLOAD_RETRY_ATTEMPTS.at(LATEST_VERSION)
}
fn default_catchup_block_download_retry_attempts() -> i64 {
    CATCHUP_BLOCK_DOWNLOAD_RETRY_ATTEMPTS.at(LATEST_VERSION)
}
fn default_tx_sync_timeout_seconds() -> i64 {
    TX_SYNC_TIMEOUT_SECONDS.at(LATEST_VERSION)
}
fn default_tx_sync_interval_seconds() -> i64 {
    TX_SYNC_INTERVAL_SECONDS.at(LATEST_VERSION)
}
fn default_tx_sync_serve_response_size() -> i64 {
    TX_SYNC_SERVE_RESPONSE_SIZE.at(LATEST_VERSION)
}
fn default_tx_backlog_service_rate_window_seconds() -> i64 {
    TX_BACKLOG_SERVICE_RATE_WINDOW_SECONDS.at(LATEST_VERSION)
}
fn default_tx_backlog_app_tx_rate_limiter_max_size() -> i64 {
    TX_BACKLOG_APP_TX_RATE_LIMITER_MAX_SIZE.at(LATEST_VERSION)
}
fn default_tx_backlog_app_tx_per_second_rate() -> i64 {
    TX_BACKLOG_APP_TX_PER_SECOND_RATE.at(LATEST_VERSION)
}
fn default_tx_backlog_app_rate_limiting_congestion_pct() -> i64 {
    TX_BACKLOG_APP_RATE_LIMITING_CONGESTION_PCT.at(LATEST_VERSION)
}
fn default_enable_tx_backlog_app_rate_limiting() -> bool {
    ENABLE_TX_BACKLOG_APP_RATE_LIMITING.at(LATEST_VERSION)
}
fn default_enable_assemble_stats() -> bool {
    ENABLE_ASSEMBLE_STATS.at(LATEST_VERSION)
}
fn default_enable_process_block_stats() -> bool {
    ENABLE_PROCESS_BLOCK_STATS.at(LATEST_VERSION)
}
fn default_max_block_history_lookback() -> u64 {
    MAX_BLOCK_HISTORY_LOOKBACK.at(LATEST_VERSION)
}
fn default_agreement_incoming_votes_queue_length() -> u64 {
    AGREEMENT_INCOMING_VOTES_QUEUE_LENGTH.at(LATEST_VERSION)
}
fn default_agreement_incoming_proposals_queue_length() -> u64 {
    AGREEMENT_INCOMING_PROPOSALS_QUEUE_LENGTH.at(LATEST_VERSION)
}
fn default_agreement_incoming_bundles_queue_length() -> u64 {
    AGREEMENT_INCOMING_BUNDLES_QUEUE_LENGTH.at(LATEST_VERSION)
}
fn default_max_acct_lookback() -> u64 {
    MAX_ACCT_LOOKBACK.at(LATEST_VERSION)
}
fn default_enable_agreement_reporting() -> bool {
    ENABLE_AGREEMENT_REPORTING.at(LATEST_VERSION)
}
fn default_enable_agreement_time_metrics() -> bool {
    ENABLE_AGREEMENT_TIME_METRICS.at(LATEST_VERSION)
}
fn default_telemetry_to_log() -> bool {
    TELEMETRY_TO_LOG.at(LATEST_VERSION)
}
fn default_base_logger_debug_level() -> u32 {
    BASE_LOGGER_DEBUG_LEVEL.at(LATEST_VERSION)
}
fn default_cadaver_size_target() -> u64 {
    CADAVER_SIZE_TARGET.at(LATEST_VERSION)
}
fn default_cadaver_directory() -> String {
    CADAVER_DIRECTORY.at(LATEST_VERSION)
}
fn default_log_size_limit() -> u64 {
    LOG_SIZE_LIMIT.at(LATEST_VERSION)
}
fn default_log_archive_name() -> String {
    LOG_ARCHIVE_NAME.at(LATEST_VERSION)
}
fn default_log_archive_max_age() -> String {
    LOG_ARCHIVE_MAX_AGE.at(LATEST_VERSION)
}
fn default_enable_profiler() -> bool {
    ENABLE_PROFILER.at(LATEST_VERSION)
}
fn default_enable_top_accounts_reporting() -> bool {
    ENABLE_TOP_ACCOUNTS_REPORTING.at(LATEST_VERSION)
}
fn default_public_address() -> String {
    PUBLIC_ADDRESS.at(LATEST_VERSION)
}
fn default_p2p_hybrid_net_address() -> String {
    P2P_HYBRID_NET_ADDRESS.at(LATEST_VERSION)
}
fn default_announce_participation_key() -> bool {
    ANNOUNCE_PARTICIPATION_KEY.at(LATEST_VERSION)
}
fn default_priority_peers() -> BTreeMap<String, bool> {
    PRIORITY_PEERS.at(LATEST_VERSION)
}
fn default_reserved_fds() -> u64 {
    RESERVED_FDS.at(LATEST_VERSION)
}
fn default_incoming_message_filter_bucket_count() -> i64 {
    INCOMING_MESSAGE_FILTER_BUCKET_COUNT.at(LATEST_VERSION)
}
fn default_incoming_message_filter_bucket_size() -> i64 {
    INCOMING_MESSAGE_FILTER_BUCKET_SIZE.at(LATEST_VERSION)
}
fn default_outgoing_message_filter_bucket_count() -> i64 {
    OUTGOING_MESSAGE_FILTER_BUCKET_COUNT.at(LATEST_VERSION)
}
fn default_outgoing_message_filter_bucket_size() -> i64 {
    OUTGOING_MESSAGE_FILTER_BUCKET_SIZE.at(LATEST_VERSION)
}
fn default_enable_outgoing_network_message_filtering() -> bool {
    ENABLE_OUTGOING_NETWORK_MESSAGE_FILTERING.at(LATEST_VERSION)
}
fn default_enable_incoming_message_filter() -> bool {
    ENABLE_INCOMING_MESSAGE_FILTER.at(LATEST_VERSION)
}
fn default_dns_security_flags() -> u32 {
    DNS_SECURITY_FLAGS.at(LATEST_VERSION)
}
fn default_network_protocol_version() -> String {
    NETWORK_PROTOCOL_VERSION.at(LATEST_VERSION)
}
fn default_use_x_forwarded_for_address_field() -> String {
    USE_X_FORWARDED_FOR_ADDRESS_FIELD.at(LATEST_VERSION)
}
fn default_disable_outgoing_connection_throttling() -> bool {
    DISABLE_OUTGOING_CONNECTION_THROTTLING.at(LATEST_VERSION)
}
fn default_disable_localhost_connection_rate_limit() -> bool {
    DISABLE_LOCALHOST_CONNECTION_RATE_LIMIT.at(LATEST_VERSION)
}
fn default_block_service_custom_fallback_endpoints() -> String {
    BLOCK_SERVICE_CUSTOM_FALLBACK_ENDPOINTS.at(LATEST_VERSION)
}
fn default_enable_request_logger() -> bool {
    ENABLE_REQUEST_LOGGER.at(LATEST_VERSION)
}
fn default_fallback_dns_resolver_address() -> String {
    FALLBACK_DNS_RESOLVER_ADDRESS.at(LATEST_VERSION)
}
fn default_p2p_private_key_location() -> String {
    P2P_PRIVATE_KEY_LOCATION.at(LATEST_VERSION)
}
fn default_enable_dht_providers() -> bool {
    ENABLE_DHT_PROVIDERS.at(LATEST_VERSION)
}
fn default_dht_mode() -> String {
    DHT_MODE.at(LATEST_VERSION)
}
fn default_enable_runtime_metrics() -> bool {
    ENABLE_RUNTIME_METRICS.at(LATEST_VERSION)
}
fn default_enable_netdev_metrics() -> bool {
    ENABLE_NET_DEV_METRICS.at(LATEST_VERSION)
}

/// Convert go's `BaseLoggerDebugLevel` (`config.Local`, go's `logging.Level`
/// in `../go-algorand/logging/log.go:51-75`: 0=Panic, 1=Fatal, 2=Error,
/// 3=Warn, 4=Info, 5=Debug) into a `tracing_subscriber::EnvFilter` directive
/// string. algod-rust's `tracing` crate has no distinct Panic/Fatal
/// severities (both terminate the process without a dedicated log level
/// below Error), so levels 0 and 1 both map to `"error"` — the closest
/// applicable severity, matching that go's Panic/Fatal logger calls still
/// emit an error-severity message before terminating. Any level above 5
/// (an operator-supplied out-of-range value) also maps to `"debug"`, go's
/// own most-verbose level, rather than panicking on an unrecognized input.
pub fn base_logger_debug_level_to_filter_directive(level: u32) -> &'static str {
    match level {
        0..=2 => "error",
        3 => "warn",
        4 => "info",
        _ => "debug",
    }
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

    /// Go: `CatchpointDir`. Wired into `algod-rust catchpoint export`/
    /// `download`'s default output directory when `--output` is omitted
    /// (issue #749). Empty string means "no override" (caller must supply
    /// an explicit output path), matching go's "falls back to
    /// ColdDataDir/datadir" semantics adapted to algod-rust's simpler
    /// one-shot-CLI catchpoint model.
    #[serde(rename = "CatchpointDir", default = "default_catchpoint_dir")]
    pub catchpoint_dir: String,

    /// Go: `StateproofDir`. **Documented no-op** — see this field's
    /// `VersionedDefault` doc comment. Round-trips through `config.json`
    /// for forward compatibility.
    #[serde(rename = "StateproofDir", default = "default_stateproof_dir")]
    pub stateproof_dir: String,

    /// Go: `HotDataDir`. Issue #953. Wired into `algod-rust participate`'s
    /// ledger/crash-db path resolution — see this field's `VersionedDefault`
    /// doc comment.
    #[serde(rename = "HotDataDir", default = "default_hot_data_dir")]
    pub hot_data_dir: String,

    /// Go: `ColdDataDir`. Issue #953. Wired into `algod-rust participate`'s
    /// ledger path resolution — see this field's `VersionedDefault` doc
    /// comment.
    #[serde(rename = "ColdDataDir", default = "default_cold_data_dir")]
    pub cold_data_dir: String,

    /// Go: `TrackerDBDir`. Issue #953. Wired into `algod-rust participate`'s
    /// tracker-database path resolution — see this field's
    /// `VersionedDefault` doc comment.
    #[serde(rename = "TrackerDBDir", default = "default_tracker_db_dir")]
    pub tracker_db_dir: String,

    /// Go: `BlockDBDir`. Issue #953. Wired into `algod-rust participate`'s
    /// block-database path resolution — see this field's `VersionedDefault`
    /// doc comment.
    #[serde(rename = "BlockDBDir", default = "default_block_db_dir")]
    pub block_db_dir: String,

    /// Go: `CrashDBDir`. Issue #953. Wired into `algod-rust participate`'s
    /// agreement crash-recovery database path resolution — see this
    /// field's `VersionedDefault` doc comment.
    #[serde(rename = "CrashDBDir", default = "default_crash_db_dir")]
    pub crash_db_dir: String,

    /// Go: `LogFileDir`. **Documented no-op** — see this field's
    /// `VersionedDefault` doc comment. Round-trips through `config.json`
    /// for forward compatibility.
    #[serde(rename = "LogFileDir", default = "default_log_file_dir")]
    pub log_file_dir: String,

    /// Go: `LogArchiveDir`. **Documented no-op** — see this field's
    /// `VersionedDefault` doc comment. Round-trips through `config.json`
    /// for forward compatibility.
    #[serde(rename = "LogArchiveDir", default = "default_log_archive_dir")]
    pub log_archive_dir: String,

    /// Go: `CatchpointInterval`. Wired into the live block-apply loop
    /// (issue #770) — see this field's `VersionedDefault` doc comment.
    #[serde(rename = "CatchpointInterval", default = "default_catchpoint_interval")]
    pub catchpoint_interval: u64,

    /// Go: `CatchpointFileHistoryLength`. Wired into automatic-generation
    /// retention (issue #770) — see this field's `VersionedDefault` doc
    /// comment.
    #[serde(
        rename = "CatchpointFileHistoryLength",
        default = "default_catchpoint_file_history_length"
    )]
    pub catchpoint_file_history_length: i64,

    /// Go: `CatchpointTracking`. Wired into [`Local::stores_catchpoints`]/
    /// [`Local::tracks_catchpoints`] (issue #770) — see this field's
    /// `VersionedDefault` doc comment.
    #[serde(rename = "CatchpointTracking", default = "default_catchpoint_tracking")]
    pub catchpoint_tracking: i64,

    /// Go: `Archival`. See the [`ARCHIVAL`] static's doc comment for the
    /// narrow scope this field is added under (issue #770): it exists
    /// solely to feed [`Local::stores_catchpoints`]'s automatic-mode gate,
    /// not as a general archival-vs-pruning-node implementation.
    #[serde(rename = "Archival", default = "default_archival")]
    pub archival: bool,

    /// Go: `OptimizeAccountsDatabaseOnStartup`. Wired into
    /// `SqliteLedger::vacuum_accounts_database` (issue #749).
    #[serde(
        rename = "OptimizeAccountsDatabaseOnStartup",
        default = "default_optimize_accounts_database_on_startup"
    )]
    pub optimize_accounts_database_on_startup: bool,

    /// Go: `LedgerSynchronousMode`. Wired into
    /// `SqliteLedger::set_synchronous_mode` (issue #749), replacing the
    /// previously-implicit (unset) SQLite `synchronous` pragma on the main
    /// ledger connection.
    #[serde(
        rename = "LedgerSynchronousMode",
        default = "default_ledger_synchronous_mode"
    )]
    pub ledger_synchronous_mode: i64,

    /// Go: `AccountsRebuildSynchronousMode`. Wired into the
    /// rebuild-shaped connections (catchpoint import/verify, catchpoint-sync
    /// bulk import) that previously hardcoded `PRAGMA synchronous=NORMAL`
    /// unconditionally (issue #749).
    #[serde(
        rename = "AccountsRebuildSynchronousMode",
        default = "default_accounts_rebuild_synchronous_mode"
    )]
    pub accounts_rebuild_synchronous_mode: i64,

    /// Go: `MaxCatchpointDownloadDuration`. Nanoseconds. Wired into
    /// `CatchpointDownloadConfig::timeout` (issue #749 fixed a prior
    /// hardcoded 30-minute value that matched neither of go's real
    /// defaults).
    #[serde(
        rename = "MaxCatchpointDownloadDuration",
        default = "default_max_catchpoint_download_duration"
    )]
    pub max_catchpoint_download_duration: i64,

    /// Go: `MinCatchpointFileDownloadBytesPerSecond`. Wired into
    /// `CatchpointDownloadConfig`'s per-chunk stall-detection timeout
    /// (issue #749).
    #[serde(
        rename = "MinCatchpointFileDownloadBytesPerSecond",
        default = "default_min_catchpoint_file_download_bytes_per_second"
    )]
    pub min_catchpoint_file_download_bytes_per_second: u64,

    /// Go: `DisableLedgerLRUCache`. Wired into `MerkleTrieCache`'s
    /// eviction (issue #749): when `true`, `evict()` becomes a no-op.
    #[serde(
        rename = "DisableLedgerLRUCache",
        default = "default_disable_ledger_lru_cache"
    )]
    pub disable_ledger_lru_cache: bool,

    /// Go: `EndpointAddress`. The headline fix of issue #751 — see
    /// [`ENDPOINT_ADDRESS`]'s doc comment for the full decision record.
    #[serde(rename = "EndpointAddress", default = "default_endpoint_address")]
    pub endpoint_address: String,

    /// Go: `RestReadTimeoutSeconds`. Wired into `ApiServer::serve` (issue
    /// #751) — see [`REST_READ_TIMEOUT_SECONDS`]'s doc comment.
    #[serde(
        rename = "RestReadTimeoutSeconds",
        default = "default_rest_read_timeout_seconds"
    )]
    pub rest_read_timeout_seconds: i64,

    /// Go: `RestWriteTimeoutSeconds`. See `rest_read_timeout_seconds`'s note.
    #[serde(
        rename = "RestWriteTimeoutSeconds",
        default = "default_rest_write_timeout_seconds"
    )]
    pub rest_write_timeout_seconds: i64,

    /// Go: `EnablePrivateNetworkAccessHeader`. Wired into the REST router's
    /// CORS middleware (issue #751).
    #[serde(
        rename = "EnablePrivateNetworkAccessHeader",
        default = "default_enable_private_network_access_header"
    )]
    pub enable_private_network_access_header: bool,

    /// Go: `RestConnectionsSoftLimit`. Wired into the REST router as a
    /// concurrency-limit admission bound (issue #751).
    #[serde(
        rename = "RestConnectionsSoftLimit",
        default = "default_rest_connections_soft_limit"
    )]
    pub rest_connections_soft_limit: u64,

    /// Go: `RestConnectionsHardLimit`. Wired into `ApiServer::serve`'s
    /// accept loop (issue #751).
    #[serde(
        rename = "RestConnectionsHardLimit",
        default = "default_rest_connections_hard_limit"
    )]
    pub rest_connections_hard_limit: u64,

    /// Go: `MaxAPIResourcesPerAccount`. Wired into
    /// `AlgodNodeInterface::max_api_resources_per_account`, replacing a
    /// prior hardcoded trait-default-only value (issue #751).
    #[serde(
        rename = "MaxAPIResourcesPerAccount",
        default = "default_max_api_resources_per_account"
    )]
    pub max_api_resources_per_account: u64,

    /// Go: `EnableUsageLog`. **Documented no-op** — see
    /// [`ENABLE_USAGE_LOG`]'s doc comment.
    #[serde(rename = "EnableUsageLog", default = "default_enable_usage_log")]
    pub enable_usage_log: bool,

    /// Go: `MaxAPIBoxPerApplication`. Same "hardcoded → configurable" fix
    /// as `max_api_resources_per_account` (issue #751).
    #[serde(
        rename = "MaxAPIBoxPerApplication",
        default = "default_max_api_box_per_application"
    )]
    pub max_api_box_per_application: u64,

    /// Go: `TxIncomingFilteringFlags`. **Documented no-op** — see
    /// [`TX_INCOMING_FILTERING_FLAGS`]'s doc comment.
    #[serde(
        rename = "TxIncomingFilteringFlags",
        default = "default_tx_incoming_filtering_flags"
    )]
    pub tx_incoming_filtering_flags: u32,

    /// Go: `EnableExperimentalAPI`. Now genuinely wired (issue #751) — see
    /// [`ENABLE_EXPERIMENTAL_API`]'s doc comment.
    #[serde(
        rename = "EnableExperimentalAPI",
        default = "default_enable_experimental_api"
    )]
    pub enable_experimental_api: bool,

    /// Go: `EnableFollowMode`. **Documented no-op / architectural decision
    /// recorded** — see [`ENABLE_FOLLOW_MODE`]'s doc comment.
    #[serde(rename = "EnableFollowMode", default = "default_enable_follow_mode")]
    pub enable_follow_mode: bool,

    /// Go: `EnableTxnEvalTracer`. **Documented no-op** — see
    /// [`ENABLE_TXN_EVAL_TRACER`]'s doc comment.
    #[serde(
        rename = "EnableTxnEvalTracer",
        default = "default_enable_txn_eval_tracer"
    )]
    pub enable_txn_eval_tracer: bool,

    /// Go: `TxIncomingFilterMaxSize`. **Documented no-op** — see
    /// [`TX_INCOMING_FILTER_MAX_SIZE`]'s doc comment.
    #[serde(
        rename = "TxIncomingFilterMaxSize",
        default = "default_tx_incoming_filter_max_size"
    )]
    pub tx_incoming_filter_max_size: u64,

    /// Go: `EnableDeveloperAPI`. **Fixes the `dev_mode` conflation bug** —
    /// see [`ENABLE_DEVELOPER_API`]'s doc comment.
    #[serde(
        rename = "EnableDeveloperAPI",
        default = "default_enable_developer_api"
    )]
    pub enable_developer_api: bool,

    /// **algod-rust-specific — no go-algorand equivalent.** go's
    /// `stateproof.Worker` is unconditionally started by every node
    /// (`node/node.go`'s `NewWorker`/`Start` calls are not gated behind any
    /// config flag); algod-rust's own state-proof signing/proving daemon
    /// (issue #814, `bin/algod-rust`'s `stateproof_service`) is
    /// deliberately opt-in instead, since it introduces a new gossip wire
    /// message type (`Tag::StateProofSig`) and autonomous transaction
    /// construction/broadcast that has not yet accumulated the same
    /// production mileage as the rest of this node's participation path.
    /// Defaults to `false`; set `"EnableStateProofWorker": true` in
    /// `config.json` to opt in.
    #[serde(rename = "EnableStateProofWorker", default)]
    pub enable_state_proof_worker: bool,

    /// Go: `CatchupParallelBlocks`. Wired into
    /// `CatchupService::start_with_parallelism` (issue #753 fixed a real
    /// behavioral gap: the periodic catchup path previously fetched blocks
    /// strictly serially with no worker pool at all).
    #[serde(
        rename = "CatchupParallelBlocks",
        default = "default_catchup_parallel_blocks"
    )]
    pub catchup_parallel_blocks: u64,

    /// Go: `CatchupFailurePeerRefreshRate`. Config-field-only (issue #753)
    /// — see [`CATCHUP_FAILURE_PEER_REFRESH_RATE`]'s doc comment.
    #[serde(
        rename = "CatchupFailurePeerRefreshRate",
        default = "default_catchup_failure_peer_refresh_rate"
    )]
    pub catchup_failure_peer_refresh_rate: i64,

    /// Go: `CatchupHTTPBlockFetchTimeoutSec`. Config-field-only (issue
    /// #753) — see [`CATCHUP_HTTP_BLOCK_FETCH_TIMEOUT_SEC`]'s doc comment.
    #[serde(
        rename = "CatchupHTTPBlockFetchTimeoutSec",
        default = "default_catchup_http_block_fetch_timeout_sec"
    )]
    pub catchup_http_block_fetch_timeout_sec: i64,

    /// Go: `CatchupGossipBlockFetchTimeoutSec`. Config-field-only (issue
    /// #753) — see [`CATCHUP_GOSSIP_BLOCK_FETCH_TIMEOUT_SEC`]'s doc comment.
    #[serde(
        rename = "CatchupGossipBlockFetchTimeoutSec",
        default = "default_catchup_gossip_block_fetch_timeout_sec"
    )]
    pub catchup_gossip_block_fetch_timeout_sec: i64,

    /// Go: `CatchupLedgerDownloadRetryAttempts`. Config-field-only (issue
    /// #753) — see [`CATCHUP_LEDGER_DOWNLOAD_RETRY_ATTEMPTS`]'s doc comment.
    #[serde(
        rename = "CatchupLedgerDownloadRetryAttempts",
        default = "default_catchup_ledger_download_retry_attempts"
    )]
    pub catchup_ledger_download_retry_attempts: i64,

    /// Go: `CatchupBlockDownloadRetryAttempts`. Config-field-only (issue
    /// #753) — see [`CATCHUP_BLOCK_DOWNLOAD_RETRY_ATTEMPTS`]'s doc comment.
    #[serde(
        rename = "CatchupBlockDownloadRetryAttempts",
        default = "default_catchup_block_download_retry_attempts"
    )]
    pub catchup_block_download_retry_attempts: i64,

    /// Go: `TxSyncTimeoutSeconds`. Wired into
    /// `algo_network::TxSyncerConfig::sync_timeout` (issue #753) — see
    /// [`TX_SYNC_TIMEOUT_SECONDS`]'s doc comment.
    #[serde(
        rename = "TxSyncTimeoutSeconds",
        default = "default_tx_sync_timeout_seconds"
    )]
    pub tx_sync_timeout_seconds: i64,

    /// Go: `TxSyncIntervalSeconds`. Wired into
    /// `algo_network::TxSyncerConfig::sync_interval` (issue #753).
    #[serde(
        rename = "TxSyncIntervalSeconds",
        default = "default_tx_sync_interval_seconds"
    )]
    pub tx_sync_interval_seconds: i64,

    /// Go: `TxSyncServeResponseSize`. Wired into
    /// `algo_network::TxSyncerConfig::server_response_size` (issue #753).
    #[serde(
        rename = "TxSyncServeResponseSize",
        default = "default_tx_sync_serve_response_size"
    )]
    pub tx_sync_serve_response_size: i64,

    /// Go: `TxBacklogServiceRateWindowSeconds`. Wired into
    /// `algo_pool::AppRateLimiter`'s sliding-window duration (issue #821)
    /// — see [`TX_BACKLOG_SERVICE_RATE_WINDOW_SECONDS`]'s doc comment.
    #[serde(
        rename = "TxBacklogServiceRateWindowSeconds",
        default = "default_tx_backlog_service_rate_window_seconds"
    )]
    pub tx_backlog_service_rate_window_seconds: i64,

    /// Go: `TxBacklogAppTxRateLimiterMaxSize`. Wired into
    /// `algo_pool::AppRateLimiter`'s max cache size (issue #821) — see
    /// [`TX_BACKLOG_APP_TX_RATE_LIMITER_MAX_SIZE`]'s doc comment.
    #[serde(
        rename = "TxBacklogAppTxRateLimiterMaxSize",
        default = "default_tx_backlog_app_tx_rate_limiter_max_size"
    )]
    pub tx_backlog_app_tx_rate_limiter_max_size: i64,

    /// Go: `TxBacklogAppTxPerSecondRate`. Wired into
    /// `algo_pool::AppRateLimiter`'s per-app-per-origin admitted rate
    /// (issue #821) — see [`TX_BACKLOG_APP_TX_PER_SECOND_RATE`]'s doc
    /// comment.
    #[serde(
        rename = "TxBacklogAppTxPerSecondRate",
        default = "default_tx_backlog_app_tx_per_second_rate"
    )]
    pub tx_backlog_app_tx_per_second_rate: i64,

    /// Go: `TxBacklogAppRateLimitingCongestionPct`. Wired into
    /// `TxTagHandler`'s congestion threshold (issue #821) — see
    /// [`TX_BACKLOG_APP_RATE_LIMITING_CONGESTION_PCT`]'s doc comment.
    #[serde(
        rename = "TxBacklogAppRateLimitingCongestionPct",
        default = "default_tx_backlog_app_rate_limiting_congestion_pct"
    )]
    pub tx_backlog_app_rate_limiting_congestion_pct: i64,

    /// Go: `EnableTxBacklogAppRateLimiting`. Wired into whether
    /// `participate` attaches an `AppRateLimiter` to its `TxTagHandler`s
    /// at all (issue #821) — see [`ENABLE_TX_BACKLOG_APP_RATE_LIMITING`]'s
    /// doc comment.
    #[serde(
        rename = "EnableTxBacklogAppRateLimiting",
        default = "default_enable_tx_backlog_app_rate_limiting"
    )]
    pub enable_tx_backlog_app_rate_limiting: bool,

    /// Go: `EnableAssembleStats`. **Documented no-op** (issue #753) — see
    /// [`ENABLE_ASSEMBLE_STATS`]'s doc comment.
    #[serde(
        rename = "EnableAssembleStats",
        default = "default_enable_assemble_stats"
    )]
    pub enable_assemble_stats: bool,

    /// Go: `EnableProcessBlockStats`. **Documented no-op** (issue #753) —
    /// see [`ENABLE_PROCESS_BLOCK_STATS`]'s doc comment.
    #[serde(
        rename = "EnableProcessBlockStats",
        default = "default_enable_process_block_stats"
    )]
    pub enable_process_block_stats: bool,

    /// Go: `MaxBlockHistoryLookback`. **Documented no-op** (issue #753) —
    /// see [`MAX_BLOCK_HISTORY_LOOKBACK`]'s doc comment.
    #[serde(
        rename = "MaxBlockHistoryLookback",
        default = "default_max_block_history_lookback"
    )]
    pub max_block_history_lookback: u64,

    /// Go: `AgreementIncomingVotesQueueLength`. Wired into
    /// `algo_network::AgreementNetworkConfig::vote_queue_len` (issue #755)
    /// — see [`AGREEMENT_INCOMING_VOTES_QUEUE_LENGTH`]'s doc comment.
    #[serde(
        rename = "AgreementIncomingVotesQueueLength",
        default = "default_agreement_incoming_votes_queue_length"
    )]
    pub agreement_incoming_votes_queue_length: u64,

    /// Go: `AgreementIncomingProposalsQueueLength`. Wired into
    /// `algo_network::AgreementNetworkConfig::proposal_queue_len` (issue
    /// #755) — **fixes a real stale-default bug**, see
    /// [`AGREEMENT_INCOMING_PROPOSALS_QUEUE_LENGTH`]'s doc comment.
    #[serde(
        rename = "AgreementIncomingProposalsQueueLength",
        default = "default_agreement_incoming_proposals_queue_length"
    )]
    pub agreement_incoming_proposals_queue_length: u64,

    /// Go: `AgreementIncomingBundlesQueueLength`. Wired into
    /// `algo_network::AgreementNetworkConfig::bundle_queue_len` (issue
    /// #755) — **fixes a real stale-default bug**, see
    /// [`AGREEMENT_INCOMING_BUNDLES_QUEUE_LENGTH`]'s doc comment.
    #[serde(
        rename = "AgreementIncomingBundlesQueueLength",
        default = "default_agreement_incoming_bundles_queue_length"
    )]
    pub agreement_incoming_bundles_queue_length: u64,

    /// Go: `MaxAcctLookback`. Wired into
    /// `SqliteLedger::set_delta_cache_window` as a *floor*, not a ceiling
    /// (issue #755) — see [`MAX_ACCT_LOOKBACK`]'s doc comment for why a
    /// literal ceiling regressed CI's live parity suite.
    #[serde(rename = "MaxAcctLookback", default = "default_max_acct_lookback")]
    pub max_acct_lookback: u64,

    /// Go: `EnableAgreementReporting`. Wired into `Tracer::new`'s first
    /// argument via `Service::with_tracer` (issue #755) — see
    /// [`ENABLE_AGREEMENT_REPORTING`]'s doc comment.
    #[serde(
        rename = "EnableAgreementReporting",
        default = "default_enable_agreement_reporting"
    )]
    pub enable_agreement_reporting: bool,

    /// Go: `EnableAgreementTimeMetrics`. Wired into `Tracer::new`'s second
    /// argument via `Service::with_tracer` (issue #755) — see
    /// [`ENABLE_AGREEMENT_TIME_METRICS`]'s doc comment.
    #[serde(
        rename = "EnableAgreementTimeMetrics",
        default = "default_enable_agreement_time_metrics"
    )]
    pub enable_agreement_time_metrics: bool,

    /// Go: `TelemetryToLog`. **Documented no-op** — see
    /// [`TELEMETRY_TO_LOG`]'s doc comment.
    #[serde(rename = "TelemetryToLog", default = "default_telemetry_to_log")]
    pub telemetry_to_log: bool,

    /// Go: `BaseLoggerDebugLevel`. Not wired into the CLI's global
    /// subscriber — see [`BASE_LOGGER_DEBUG_LEVEL`]'s doc comment and
    /// [`base_logger_debug_level_to_filter_directive`].
    #[serde(
        rename = "BaseLoggerDebugLevel",
        default = "default_base_logger_debug_level"
    )]
    pub base_logger_debug_level: u32,

    /// Go: `CadaverSizeTarget`. `0` disables cadaver tracing. See
    /// [`CADAVER_SIZE_TARGET`]'s doc comment and
    /// `algo_agreement::trace::resolve_cadaver_config`.
    #[serde(rename = "CadaverSizeTarget", default = "default_cadaver_size_target")]
    pub cadaver_size_target: u64,

    /// Go: `CadaverDirectory`. See [`CADAVER_DIRECTORY`]'s doc comment.
    #[serde(rename = "CadaverDirectory", default = "default_cadaver_directory")]
    pub cadaver_directory: String,

    /// Go: `LogSizeLimit`. **Documented no-op** — see [`LOG_SIZE_LIMIT`]'s
    /// doc comment.
    #[serde(rename = "LogSizeLimit", default = "default_log_size_limit")]
    pub log_size_limit: u64,

    /// Go: `LogArchiveName`. **Documented no-op** — see
    /// [`LOG_ARCHIVE_NAME`]'s doc comment.
    #[serde(rename = "LogArchiveName", default = "default_log_archive_name")]
    pub log_archive_name: String,

    /// Go: `LogArchiveMaxAge`. **Documented no-op** — see
    /// [`LOG_ARCHIVE_MAX_AGE`]'s doc comment.
    #[serde(rename = "LogArchiveMaxAge", default = "default_log_archive_max_age")]
    pub log_archive_max_age: String,

    /// Go: `EnableProfiler`. **Documented no-op** — see [`ENABLE_PROFILER`]'s
    /// doc comment.
    #[serde(rename = "EnableProfiler", default = "default_enable_profiler")]
    pub enable_profiler: bool,

    /// Go: `EnableTopAccountsReporting`. **Documented not-applicable**
    /// (upstream's own "Deprecated, do not use") — see
    /// [`ENABLE_TOP_ACCOUNTS_REPORTING`]'s doc comment.
    #[serde(
        rename = "EnableTopAccountsReporting",
        default = "default_enable_top_accounts_reporting"
    )]
    pub enable_top_accounts_reporting: bool,

    // --- Remaining networking fields (issue #768) ------------------------
    /// Go: `PublicAddress`. Round-trip only — see the module note above
    /// [`PUBLIC_ADDRESS`].
    #[serde(rename = "PublicAddress", default = "default_public_address")]
    pub public_address: String,

    /// Go: `P2PHybridNetAddress`. Round-trip only — see
    /// [`P2P_HYBRID_NET_ADDRESS`]'s doc comment.
    #[serde(
        rename = "P2PHybridNetAddress",
        default = "default_p2p_hybrid_net_address"
    )]
    pub p2p_hybrid_net_address: String,

    /// Go: `AnnounceParticipationKey`. Round-trip only — see
    /// [`ANNOUNCE_PARTICIPATION_KEY`]'s doc comment.
    #[serde(
        rename = "AnnounceParticipationKey",
        default = "default_announce_participation_key"
    )]
    pub announce_participation_key: bool,

    /// Go: `PriorityPeers`. Round-trip only, but demonstrates the
    /// non-`Copy` `VersionedDefault<BTreeMap<String, bool>>` shape — see
    /// [`PRIORITY_PEERS`]'s doc comment.
    #[serde(rename = "PriorityPeers", default = "default_priority_peers")]
    pub priority_peers: BTreeMap<String, bool>,

    /// Go: `ReservedFDs`. Round-trip only — see [`RESERVED_FDS`]'s doc
    /// comment.
    #[serde(rename = "ReservedFDs", default = "default_reserved_fds")]
    pub reserved_fds: u64,

    /// Go: `IncomingMessageFilterBucketCount`. Wired into `algo-network`'s
    /// incoming `MessageFilter` bucket construction — see
    /// [`INCOMING_MESSAGE_FILTER_BUCKET_COUNT`]'s doc comment.
    #[serde(
        rename = "IncomingMessageFilterBucketCount",
        default = "default_incoming_message_filter_bucket_count"
    )]
    pub incoming_message_filter_bucket_count: i64,

    /// Go: `IncomingMessageFilterBucketSize`. Wired into `algo-network`'s
    /// incoming `MessageFilter` bucket construction — see
    /// [`INCOMING_MESSAGE_FILTER_BUCKET_SIZE`]'s doc comment.
    #[serde(
        rename = "IncomingMessageFilterBucketSize",
        default = "default_incoming_message_filter_bucket_size"
    )]
    pub incoming_message_filter_bucket_size: i64,

    /// Go: `OutgoingMessageFilterBucketCount`. Wired into `algo-network`'s
    /// outgoing `MessageFilter` bucket construction.
    #[serde(
        rename = "OutgoingMessageFilterBucketCount",
        default = "default_outgoing_message_filter_bucket_count"
    )]
    pub outgoing_message_filter_bucket_count: i64,

    /// Go: `OutgoingMessageFilterBucketSize`. Wired into `algo-network`'s
    /// outgoing `MessageFilter` bucket construction.
    #[serde(
        rename = "OutgoingMessageFilterBucketSize",
        default = "default_outgoing_message_filter_bucket_size"
    )]
    pub outgoing_message_filter_bucket_size: i64,

    /// Go: `EnableOutgoingNetworkMessageFiltering`. Wired: gates whether an
    /// outgoing `MessageFilter` is constructed at all.
    #[serde(
        rename = "EnableOutgoingNetworkMessageFiltering",
        default = "default_enable_outgoing_network_message_filtering"
    )]
    pub enable_outgoing_network_message_filtering: bool,

    /// Go: `EnableIncomingMessageFilter`. Wired: gates whether an incoming
    /// `MessageFilter` is constructed at all.
    #[serde(
        rename = "EnableIncomingMessageFilter",
        default = "default_enable_incoming_message_filter"
    )]
    pub enable_incoming_message_filter: bool,

    /// Go: `DNSSecurityFlags`. Round-trip only — see
    /// [`DNS_SECURITY_FLAGS`]'s doc comment.
    #[serde(rename = "DNSSecurityFlags", default = "default_dns_security_flags")]
    pub dns_security_flags: u32,

    /// Go: `NetworkProtocolVersion`. Round-trip only — see
    /// [`NETWORK_PROTOCOL_VERSION`]'s doc comment.
    #[serde(
        rename = "NetworkProtocolVersion",
        default = "default_network_protocol_version"
    )]
    pub network_protocol_version: String,

    /// Go: `UseXForwardedForAddressField`. Round-trip only — see
    /// [`USE_X_FORWARDED_FOR_ADDRESS_FIELD`]'s doc comment.
    #[serde(
        rename = "UseXForwardedForAddressField",
        default = "default_use_x_forwarded_for_address_field"
    )]
    pub use_x_forwarded_for_address_field: String,

    /// Go: `DisableOutgoingConnectionThrottling`. Round-trip only — see
    /// [`DISABLE_OUTGOING_CONNECTION_THROTTLING`]'s doc comment.
    #[serde(
        rename = "DisableOutgoingConnectionThrottling",
        default = "default_disable_outgoing_connection_throttling"
    )]
    pub disable_outgoing_connection_throttling: bool,

    /// Go: `DisableLocalhostConnectionRateLimit`. Wired into
    /// `algo_network::ConnectionTracker` — see
    /// [`DISABLE_LOCALHOST_CONNECTION_RATE_LIMIT`]'s doc comment.
    #[serde(
        rename = "DisableLocalhostConnectionRateLimit",
        default = "default_disable_localhost_connection_rate_limit"
    )]
    pub disable_localhost_connection_rate_limit: bool,

    /// Go: `BlockServiceCustomFallbackEndpoints`. Round-trip only — see
    /// [`BLOCK_SERVICE_CUSTOM_FALLBACK_ENDPOINTS`]'s doc comment.
    #[serde(
        rename = "BlockServiceCustomFallbackEndpoints",
        default = "default_block_service_custom_fallback_endpoints"
    )]
    pub block_service_custom_fallback_endpoints: String,

    /// Go: `EnableRequestLogger`. Round-trip only — see
    /// [`ENABLE_REQUEST_LOGGER`]'s doc comment.
    #[serde(
        rename = "EnableRequestLogger",
        default = "default_enable_request_logger"
    )]
    pub enable_request_logger: bool,

    /// Go: `FallbackDNSResolverAddress`. Round-trip only — see
    /// [`FALLBACK_DNS_RESOLVER_ADDRESS`]'s doc comment.
    #[serde(
        rename = "FallbackDNSResolverAddress",
        default = "default_fallback_dns_resolver_address"
    )]
    pub fallback_dns_resolver_address: String,

    /// Go: `P2PPrivateKeyLocation`. Wired as a custom-path override for
    /// the P2P peer-ID private key file — see
    /// [`P2P_PRIVATE_KEY_LOCATION`]'s doc comment.
    #[serde(
        rename = "P2PPrivateKeyLocation",
        default = "default_p2p_private_key_location"
    )]
    pub p2p_private_key_location: String,

    /// Go: `EnableDHTProviders`. Wired into `algo_p2p::dht` — see
    /// [`ENABLE_DHT_PROVIDERS`]'s doc comment.
    #[serde(
        rename = "EnableDHTProviders",
        default = "default_enable_dht_providers"
    )]
    pub enable_dht_providers: bool,

    /// Go: `DHTMode`. Wired into `algo_p2p::dht` — see [`DHT_MODE`]'s doc
    /// comment.
    #[serde(rename = "DHTMode", default = "default_dht_mode")]
    pub dht_mode: String,

    /// Go: `EnableRuntimeMetrics`. Wired into
    /// `AlgodNodeInterface::metrics_exposition` (issue #776) — see
    /// [`ENABLE_RUNTIME_METRICS`]'s doc comment.
    #[serde(
        rename = "EnableRuntimeMetrics",
        default = "default_enable_runtime_metrics"
    )]
    pub enable_runtime_metrics: bool,

    /// Go: `EnableNetDevMetrics`. Wired into
    /// `AlgodNodeInterface::metrics_exposition` (issue #776) — see
    /// [`ENABLE_NET_DEV_METRICS`]'s doc comment.
    #[serde(
        rename = "EnableNetDevMetrics",
        default = "default_enable_netdev_metrics"
    )]
    pub enable_netdev_metrics: bool,
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
            catchpoint_dir: CATCHPOINT_DIR.at(version),
            stateproof_dir: STATEPROOF_DIR.at(version),
            hot_data_dir: HOT_DATA_DIR.at(version),
            cold_data_dir: COLD_DATA_DIR.at(version),
            tracker_db_dir: TRACKER_DB_DIR.at(version),
            block_db_dir: BLOCK_DB_DIR.at(version),
            crash_db_dir: CRASH_DB_DIR.at(version),
            log_file_dir: LOG_FILE_DIR.at(version),
            log_archive_dir: LOG_ARCHIVE_DIR.at(version),
            catchpoint_interval: CATCHPOINT_INTERVAL.at(version),
            catchpoint_file_history_length: CATCHPOINT_FILE_HISTORY_LENGTH.at(version),
            catchpoint_tracking: CATCHPOINT_TRACKING.at(version),
            archival: ARCHIVAL.at(version),
            optimize_accounts_database_on_startup: OPTIMIZE_ACCOUNTS_DATABASE_ON_STARTUP
                .at(version),
            ledger_synchronous_mode: LEDGER_SYNCHRONOUS_MODE.at(version),
            accounts_rebuild_synchronous_mode: ACCOUNTS_REBUILD_SYNCHRONOUS_MODE.at(version),
            max_catchpoint_download_duration: MAX_CATCHPOINT_DOWNLOAD_DURATION.at(version),
            min_catchpoint_file_download_bytes_per_second:
                MIN_CATCHPOINT_FILE_DOWNLOAD_BYTES_PER_SECOND.at(version),
            disable_ledger_lru_cache: DISABLE_LEDGER_LRU_CACHE.at(version),
            endpoint_address: ENDPOINT_ADDRESS.at(version),
            rest_read_timeout_seconds: REST_READ_TIMEOUT_SECONDS.at(version),
            rest_write_timeout_seconds: REST_WRITE_TIMEOUT_SECONDS.at(version),
            enable_private_network_access_header: ENABLE_PRIVATE_NETWORK_ACCESS_HEADER.at(version),
            rest_connections_soft_limit: REST_CONNECTIONS_SOFT_LIMIT.at(version),
            rest_connections_hard_limit: REST_CONNECTIONS_HARD_LIMIT.at(version),
            max_api_resources_per_account: MAX_API_RESOURCES_PER_ACCOUNT.at(version),
            enable_usage_log: ENABLE_USAGE_LOG.at(version),
            max_api_box_per_application: MAX_API_BOX_PER_APPLICATION.at(version),
            tx_incoming_filtering_flags: TX_INCOMING_FILTERING_FLAGS.at(version),
            enable_experimental_api: ENABLE_EXPERIMENTAL_API.at(version),
            enable_follow_mode: ENABLE_FOLLOW_MODE.at(version),
            enable_txn_eval_tracer: ENABLE_TXN_EVAL_TRACER.at(version),
            tx_incoming_filter_max_size: TX_INCOMING_FILTER_MAX_SIZE.at(version),
            enable_developer_api: ENABLE_DEVELOPER_API.at(version),
            enable_state_proof_worker: false,
            catchup_parallel_blocks: CATCHUP_PARALLEL_BLOCKS.at(version),
            catchup_failure_peer_refresh_rate: CATCHUP_FAILURE_PEER_REFRESH_RATE.at(version),
            catchup_http_block_fetch_timeout_sec: CATCHUP_HTTP_BLOCK_FETCH_TIMEOUT_SEC.at(version),
            catchup_gossip_block_fetch_timeout_sec: CATCHUP_GOSSIP_BLOCK_FETCH_TIMEOUT_SEC
                .at(version),
            catchup_ledger_download_retry_attempts: CATCHUP_LEDGER_DOWNLOAD_RETRY_ATTEMPTS
                .at(version),
            catchup_block_download_retry_attempts: CATCHUP_BLOCK_DOWNLOAD_RETRY_ATTEMPTS
                .at(version),
            tx_sync_timeout_seconds: TX_SYNC_TIMEOUT_SECONDS.at(version),
            tx_sync_interval_seconds: TX_SYNC_INTERVAL_SECONDS.at(version),
            tx_sync_serve_response_size: TX_SYNC_SERVE_RESPONSE_SIZE.at(version),
            tx_backlog_service_rate_window_seconds: TX_BACKLOG_SERVICE_RATE_WINDOW_SECONDS
                .at(version),
            tx_backlog_app_tx_rate_limiter_max_size: TX_BACKLOG_APP_TX_RATE_LIMITER_MAX_SIZE
                .at(version),
            tx_backlog_app_tx_per_second_rate: TX_BACKLOG_APP_TX_PER_SECOND_RATE.at(version),
            tx_backlog_app_rate_limiting_congestion_pct:
                TX_BACKLOG_APP_RATE_LIMITING_CONGESTION_PCT.at(version),
            enable_tx_backlog_app_rate_limiting: ENABLE_TX_BACKLOG_APP_RATE_LIMITING.at(version),
            enable_assemble_stats: ENABLE_ASSEMBLE_STATS.at(version),
            enable_process_block_stats: ENABLE_PROCESS_BLOCK_STATS.at(version),
            max_block_history_lookback: MAX_BLOCK_HISTORY_LOOKBACK.at(version),
            agreement_incoming_votes_queue_length: AGREEMENT_INCOMING_VOTES_QUEUE_LENGTH
                .at(version),
            agreement_incoming_proposals_queue_length: AGREEMENT_INCOMING_PROPOSALS_QUEUE_LENGTH
                .at(version),
            agreement_incoming_bundles_queue_length: AGREEMENT_INCOMING_BUNDLES_QUEUE_LENGTH
                .at(version),
            max_acct_lookback: MAX_ACCT_LOOKBACK.at(version),
            enable_agreement_reporting: ENABLE_AGREEMENT_REPORTING.at(version),
            enable_agreement_time_metrics: ENABLE_AGREEMENT_TIME_METRICS.at(version),
            telemetry_to_log: TELEMETRY_TO_LOG.at(version),
            base_logger_debug_level: BASE_LOGGER_DEBUG_LEVEL.at(version),
            cadaver_size_target: CADAVER_SIZE_TARGET.at(version),
            cadaver_directory: CADAVER_DIRECTORY.at(version),
            log_size_limit: LOG_SIZE_LIMIT.at(version),
            log_archive_name: LOG_ARCHIVE_NAME.at(version),
            log_archive_max_age: LOG_ARCHIVE_MAX_AGE.at(version),
            enable_profiler: ENABLE_PROFILER.at(version),
            enable_top_accounts_reporting: ENABLE_TOP_ACCOUNTS_REPORTING.at(version),
            public_address: PUBLIC_ADDRESS.at(version),
            p2p_hybrid_net_address: P2P_HYBRID_NET_ADDRESS.at(version),
            announce_participation_key: ANNOUNCE_PARTICIPATION_KEY.at(version),
            priority_peers: PRIORITY_PEERS.at(version),
            reserved_fds: RESERVED_FDS.at(version),
            incoming_message_filter_bucket_count: INCOMING_MESSAGE_FILTER_BUCKET_COUNT.at(version),
            incoming_message_filter_bucket_size: INCOMING_MESSAGE_FILTER_BUCKET_SIZE.at(version),
            outgoing_message_filter_bucket_count: OUTGOING_MESSAGE_FILTER_BUCKET_COUNT.at(version),
            outgoing_message_filter_bucket_size: OUTGOING_MESSAGE_FILTER_BUCKET_SIZE.at(version),
            enable_outgoing_network_message_filtering: ENABLE_OUTGOING_NETWORK_MESSAGE_FILTERING
                .at(version),
            enable_incoming_message_filter: ENABLE_INCOMING_MESSAGE_FILTER.at(version),
            dns_security_flags: DNS_SECURITY_FLAGS.at(version),
            network_protocol_version: NETWORK_PROTOCOL_VERSION.at(version),
            use_x_forwarded_for_address_field: USE_X_FORWARDED_FOR_ADDRESS_FIELD.at(version),
            disable_outgoing_connection_throttling: DISABLE_OUTGOING_CONNECTION_THROTTLING
                .at(version),
            disable_localhost_connection_rate_limit: DISABLE_LOCALHOST_CONNECTION_RATE_LIMIT
                .at(version),
            block_service_custom_fallback_endpoints: BLOCK_SERVICE_CUSTOM_FALLBACK_ENDPOINTS
                .at(version),
            enable_request_logger: ENABLE_REQUEST_LOGGER.at(version),
            fallback_dns_resolver_address: FALLBACK_DNS_RESOLVER_ADDRESS.at(version),
            p2p_private_key_location: P2P_PRIVATE_KEY_LOCATION.at(version),
            enable_dht_providers: ENABLE_DHT_PROVIDERS.at(version),
            dht_mode: DHT_MODE.at(version),
            enable_runtime_metrics: ENABLE_RUNTIME_METRICS.at(version),
            enable_netdev_metrics: ENABLE_NET_DEV_METRICS.at(version),
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
            migrate_field(&mut self.catchpoint_dir, &CATCHPOINT_DIR, cur, next);
            migrate_field(&mut self.stateproof_dir, &STATEPROOF_DIR, cur, next);
            migrate_field(&mut self.hot_data_dir, &HOT_DATA_DIR, cur, next);
            migrate_field(&mut self.cold_data_dir, &COLD_DATA_DIR, cur, next);
            migrate_field(&mut self.tracker_db_dir, &TRACKER_DB_DIR, cur, next);
            migrate_field(&mut self.block_db_dir, &BLOCK_DB_DIR, cur, next);
            migrate_field(&mut self.crash_db_dir, &CRASH_DB_DIR, cur, next);
            migrate_field(&mut self.log_file_dir, &LOG_FILE_DIR, cur, next);
            migrate_field(&mut self.log_archive_dir, &LOG_ARCHIVE_DIR, cur, next);
            migrate_field(
                &mut self.catchpoint_interval,
                &CATCHPOINT_INTERVAL,
                cur,
                next,
            );
            migrate_field(
                &mut self.catchpoint_file_history_length,
                &CATCHPOINT_FILE_HISTORY_LENGTH,
                cur,
                next,
            );
            migrate_field(
                &mut self.catchpoint_tracking,
                &CATCHPOINT_TRACKING,
                cur,
                next,
            );
            migrate_field(&mut self.archival, &ARCHIVAL, cur, next);
            migrate_field(
                &mut self.optimize_accounts_database_on_startup,
                &OPTIMIZE_ACCOUNTS_DATABASE_ON_STARTUP,
                cur,
                next,
            );
            migrate_field(
                &mut self.ledger_synchronous_mode,
                &LEDGER_SYNCHRONOUS_MODE,
                cur,
                next,
            );
            migrate_field(
                &mut self.accounts_rebuild_synchronous_mode,
                &ACCOUNTS_REBUILD_SYNCHRONOUS_MODE,
                cur,
                next,
            );
            migrate_field(
                &mut self.max_catchpoint_download_duration,
                &MAX_CATCHPOINT_DOWNLOAD_DURATION,
                cur,
                next,
            );
            migrate_field(
                &mut self.min_catchpoint_file_download_bytes_per_second,
                &MIN_CATCHPOINT_FILE_DOWNLOAD_BYTES_PER_SECOND,
                cur,
                next,
            );
            migrate_field(
                &mut self.disable_ledger_lru_cache,
                &DISABLE_LEDGER_LRU_CACHE,
                cur,
                next,
            );
            migrate_field(&mut self.endpoint_address, &ENDPOINT_ADDRESS, cur, next);
            migrate_field(
                &mut self.rest_read_timeout_seconds,
                &REST_READ_TIMEOUT_SECONDS,
                cur,
                next,
            );
            migrate_field(
                &mut self.rest_write_timeout_seconds,
                &REST_WRITE_TIMEOUT_SECONDS,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_private_network_access_header,
                &ENABLE_PRIVATE_NETWORK_ACCESS_HEADER,
                cur,
                next,
            );
            migrate_field(
                &mut self.rest_connections_soft_limit,
                &REST_CONNECTIONS_SOFT_LIMIT,
                cur,
                next,
            );
            migrate_field(
                &mut self.rest_connections_hard_limit,
                &REST_CONNECTIONS_HARD_LIMIT,
                cur,
                next,
            );
            migrate_field(
                &mut self.max_api_resources_per_account,
                &MAX_API_RESOURCES_PER_ACCOUNT,
                cur,
                next,
            );
            migrate_field(&mut self.enable_usage_log, &ENABLE_USAGE_LOG, cur, next);
            migrate_field(
                &mut self.max_api_box_per_application,
                &MAX_API_BOX_PER_APPLICATION,
                cur,
                next,
            );
            migrate_field(
                &mut self.tx_incoming_filtering_flags,
                &TX_INCOMING_FILTERING_FLAGS,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_experimental_api,
                &ENABLE_EXPERIMENTAL_API,
                cur,
                next,
            );
            migrate_field(&mut self.enable_follow_mode, &ENABLE_FOLLOW_MODE, cur, next);
            migrate_field(
                &mut self.enable_txn_eval_tracer,
                &ENABLE_TXN_EVAL_TRACER,
                cur,
                next,
            );
            migrate_field(
                &mut self.tx_incoming_filter_max_size,
                &TX_INCOMING_FILTER_MAX_SIZE,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_developer_api,
                &ENABLE_DEVELOPER_API,
                cur,
                next,
            );
            migrate_field(
                &mut self.catchup_parallel_blocks,
                &CATCHUP_PARALLEL_BLOCKS,
                cur,
                next,
            );
            migrate_field(
                &mut self.catchup_failure_peer_refresh_rate,
                &CATCHUP_FAILURE_PEER_REFRESH_RATE,
                cur,
                next,
            );
            migrate_field(
                &mut self.catchup_http_block_fetch_timeout_sec,
                &CATCHUP_HTTP_BLOCK_FETCH_TIMEOUT_SEC,
                cur,
                next,
            );
            migrate_field(
                &mut self.catchup_gossip_block_fetch_timeout_sec,
                &CATCHUP_GOSSIP_BLOCK_FETCH_TIMEOUT_SEC,
                cur,
                next,
            );
            migrate_field(
                &mut self.catchup_ledger_download_retry_attempts,
                &CATCHUP_LEDGER_DOWNLOAD_RETRY_ATTEMPTS,
                cur,
                next,
            );
            migrate_field(
                &mut self.catchup_block_download_retry_attempts,
                &CATCHUP_BLOCK_DOWNLOAD_RETRY_ATTEMPTS,
                cur,
                next,
            );
            migrate_field(
                &mut self.tx_sync_timeout_seconds,
                &TX_SYNC_TIMEOUT_SECONDS,
                cur,
                next,
            );
            migrate_field(
                &mut self.tx_sync_interval_seconds,
                &TX_SYNC_INTERVAL_SECONDS,
                cur,
                next,
            );
            migrate_field(
                &mut self.tx_sync_serve_response_size,
                &TX_SYNC_SERVE_RESPONSE_SIZE,
                cur,
                next,
            );
            migrate_field(
                &mut self.tx_backlog_service_rate_window_seconds,
                &TX_BACKLOG_SERVICE_RATE_WINDOW_SECONDS,
                cur,
                next,
            );
            migrate_field(
                &mut self.tx_backlog_app_tx_rate_limiter_max_size,
                &TX_BACKLOG_APP_TX_RATE_LIMITER_MAX_SIZE,
                cur,
                next,
            );
            migrate_field(
                &mut self.tx_backlog_app_tx_per_second_rate,
                &TX_BACKLOG_APP_TX_PER_SECOND_RATE,
                cur,
                next,
            );
            migrate_field(
                &mut self.tx_backlog_app_rate_limiting_congestion_pct,
                &TX_BACKLOG_APP_RATE_LIMITING_CONGESTION_PCT,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_tx_backlog_app_rate_limiting,
                &ENABLE_TX_BACKLOG_APP_RATE_LIMITING,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_assemble_stats,
                &ENABLE_ASSEMBLE_STATS,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_process_block_stats,
                &ENABLE_PROCESS_BLOCK_STATS,
                cur,
                next,
            );
            migrate_field(
                &mut self.max_block_history_lookback,
                &MAX_BLOCK_HISTORY_LOOKBACK,
                cur,
                next,
            );
            migrate_field(
                &mut self.agreement_incoming_votes_queue_length,
                &AGREEMENT_INCOMING_VOTES_QUEUE_LENGTH,
                cur,
                next,
            );
            migrate_field(
                &mut self.agreement_incoming_proposals_queue_length,
                &AGREEMENT_INCOMING_PROPOSALS_QUEUE_LENGTH,
                cur,
                next,
            );
            migrate_field(
                &mut self.agreement_incoming_bundles_queue_length,
                &AGREEMENT_INCOMING_BUNDLES_QUEUE_LENGTH,
                cur,
                next,
            );
            migrate_field(&mut self.max_acct_lookback, &MAX_ACCT_LOOKBACK, cur, next);
            migrate_field(
                &mut self.enable_agreement_reporting,
                &ENABLE_AGREEMENT_REPORTING,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_agreement_time_metrics,
                &ENABLE_AGREEMENT_TIME_METRICS,
                cur,
                next,
            );
            migrate_field(&mut self.telemetry_to_log, &TELEMETRY_TO_LOG, cur, next);
            migrate_field(
                &mut self.base_logger_debug_level,
                &BASE_LOGGER_DEBUG_LEVEL,
                cur,
                next,
            );
            migrate_field(
                &mut self.cadaver_size_target,
                &CADAVER_SIZE_TARGET,
                cur,
                next,
            );
            migrate_field(&mut self.cadaver_directory, &CADAVER_DIRECTORY, cur, next);
            migrate_field(&mut self.log_size_limit, &LOG_SIZE_LIMIT, cur, next);
            migrate_field(&mut self.log_archive_name, &LOG_ARCHIVE_NAME, cur, next);
            migrate_field(
                &mut self.log_archive_max_age,
                &LOG_ARCHIVE_MAX_AGE,
                cur,
                next,
            );
            migrate_field(&mut self.enable_profiler, &ENABLE_PROFILER, cur, next);
            migrate_field(
                &mut self.enable_top_accounts_reporting,
                &ENABLE_TOP_ACCOUNTS_REPORTING,
                cur,
                next,
            );
            migrate_field(&mut self.public_address, &PUBLIC_ADDRESS, cur, next);
            migrate_field(
                &mut self.p2p_hybrid_net_address,
                &P2P_HYBRID_NET_ADDRESS,
                cur,
                next,
            );
            migrate_field(
                &mut self.announce_participation_key,
                &ANNOUNCE_PARTICIPATION_KEY,
                cur,
                next,
            );
            migrate_field(&mut self.priority_peers, &PRIORITY_PEERS, cur, next);
            migrate_field(&mut self.reserved_fds, &RESERVED_FDS, cur, next);
            migrate_field(
                &mut self.incoming_message_filter_bucket_count,
                &INCOMING_MESSAGE_FILTER_BUCKET_COUNT,
                cur,
                next,
            );
            migrate_field(
                &mut self.incoming_message_filter_bucket_size,
                &INCOMING_MESSAGE_FILTER_BUCKET_SIZE,
                cur,
                next,
            );
            migrate_field(
                &mut self.outgoing_message_filter_bucket_count,
                &OUTGOING_MESSAGE_FILTER_BUCKET_COUNT,
                cur,
                next,
            );
            migrate_field(
                &mut self.outgoing_message_filter_bucket_size,
                &OUTGOING_MESSAGE_FILTER_BUCKET_SIZE,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_outgoing_network_message_filtering,
                &ENABLE_OUTGOING_NETWORK_MESSAGE_FILTERING,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_incoming_message_filter,
                &ENABLE_INCOMING_MESSAGE_FILTER,
                cur,
                next,
            );
            migrate_field(&mut self.dns_security_flags, &DNS_SECURITY_FLAGS, cur, next);
            migrate_field(
                &mut self.network_protocol_version,
                &NETWORK_PROTOCOL_VERSION,
                cur,
                next,
            );
            migrate_field(
                &mut self.use_x_forwarded_for_address_field,
                &USE_X_FORWARDED_FOR_ADDRESS_FIELD,
                cur,
                next,
            );
            migrate_field(
                &mut self.disable_outgoing_connection_throttling,
                &DISABLE_OUTGOING_CONNECTION_THROTTLING,
                cur,
                next,
            );
            migrate_field(
                &mut self.disable_localhost_connection_rate_limit,
                &DISABLE_LOCALHOST_CONNECTION_RATE_LIMIT,
                cur,
                next,
            );
            migrate_field(
                &mut self.block_service_custom_fallback_endpoints,
                &BLOCK_SERVICE_CUSTOM_FALLBACK_ENDPOINTS,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_request_logger,
                &ENABLE_REQUEST_LOGGER,
                cur,
                next,
            );
            migrate_field(
                &mut self.fallback_dns_resolver_address,
                &FALLBACK_DNS_RESOLVER_ADDRESS,
                cur,
                next,
            );
            migrate_field(
                &mut self.p2p_private_key_location,
                &P2P_PRIVATE_KEY_LOCATION,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_dht_providers,
                &ENABLE_DHT_PROVIDERS,
                cur,
                next,
            );
            migrate_field(&mut self.dht_mode, &DHT_MODE, cur, next);
            migrate_field(
                &mut self.enable_runtime_metrics,
                &ENABLE_RUNTIME_METRICS,
                cur,
                next,
            );
            migrate_field(
                &mut self.enable_netdev_metrics,
                &ENABLE_NET_DEV_METRICS,
                cur,
                next,
            );
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

    /// Returns `true` if the node is configured to *write catchpoint files
    /// to disk*. Mirrors go's `config.Local.StoresCatchpoints()`
    /// (`config/localTemplate.go:1052-1069`) exactly, including its
    /// "unrecognized `CatchpointTracking` value behaves like Automatic"
    /// `default: fallthrough` case.
    ///
    /// Consulted by the live block-apply loop (issue #770,
    /// `algo_ledger::sqlite::SqliteLedger::commit_block`) to gate automatic
    /// interval-driven catchpoint generation, and available to
    /// `algod-rust catchpoint export` callers that want to match the same
    /// resolution the live loop uses.
    pub fn stores_catchpoints(&self) -> bool {
        // Go compares `CatchpointInterval <= 0`; the field here is `u64`
        // (matching go's own field type), so `<= 0` degenerates to `== 0`.
        if self.catchpoint_interval == 0 {
            return false;
        }
        match self.catchpoint_tracking {
            CATCHPOINT_TRACKING_MODE_UNTRACKED => false,
            CATCHPOINT_TRACKING_MODE_STORED => true,
            // Go's `switch` has an explicit `case Automatic, Tracked:` arm
            // plus a `default: fallthrough` into it — i.e. every value
            // other than Untracked/Stored resolves the same way. Matched
            // here with an unconditional fallback for that reason, not as
            // a shortcut.
            CATCHPOINT_TRACKING_MODE_AUTOMATIC | CATCHPOINT_TRACKING_MODE_TRACKED => self.archival,
            _ => self.archival,
        }
    }

    /// Returns `true` if the node is configured to *track* catchpoints —
    /// a superset of [`Self::stores_catchpoints`] that also covers
    /// `CatchpointTracking == Tracked` with a non-archival node (tracked,
    /// not written to disk). Mirrors go's
    /// `config.Local.TracksCatchpoints()` (`config/localTemplate.go:1072-1080`).
    ///
    /// algod-rust does not yet implement the "tracked but not stored"
    /// mode's underlying mechanism (an in-memory-only merkle-trie
    /// bookkeeping path with no file write) — this method is provided for
    /// parity/completeness and future callers, but issue #770's automatic
    /// file-generation wiring only consults [`Self::stores_catchpoints`].
    pub fn tracks_catchpoints(&self) -> bool {
        if self.stores_catchpoints() {
            return true;
        }
        self.catchpoint_tracking == CATCHPOINT_TRACKING_MODE_TRACKED && self.catchpoint_interval > 0
    }

    /// Go: `enrichNetworkingConfig`'s `GossipFanout` bump
    /// (`config/config.go:170-179`): a listen-server node's `GossipFanout`
    /// gets substituted with [`DEFAULT_RELAY_GOSSIP_FANOUT`] (go's
    /// `defaultRelayGossipFanout`, 8) *unless* the operator already
    /// overrode it away from the ordinary default (4) in `config.json` —
    /// mirroring go's exact gate, `source.GossipFanout ==
    /// defaultLocal.GossipFanout`, an equality check against the default
    /// rather than an "was this field present in the JSON" flag.
    ///
    /// algod-rust has no `NetAddress` field on [`Local`] itself to key this
    /// off automatically (its equivalent is the CLI-flag-per-subcommand
    /// `relay --bind-address` / `participate --listen-address` design —
    /// see the module docs' "Explicitly out of scope" note and issue
    /// #788's PR description for why full field unification onto a shared
    /// `Local::net_address` wasn't warranted). Callers that already know
    /// they are acting as a listen server (`relay`: unconditionally;
    /// `participate`: only once `--listen-address` resolves to `Some`)
    /// call this explicitly instead.
    ///
    /// `EnableLedgerService`/`EnableBlockService` auto-enable and
    /// `PublicAddress` lowercasing — the other two `enrichNetworkingConfig`
    /// side effects — are deliberately NOT implemented anywhere:
    /// `enable_ledger_service`/`enable_block_service` are already
    /// documented, deliberate no-ops in this crate (see their own doc
    /// comments) with no runtime behavior to gate, so auto-flipping them
    /// would only change which no-op flag reads `true`; `public_address`
    /// remains round-trip-only (no behavioral use anywhere in algod-rust
    /// yet), so lowercasing it would be normalizing a value nothing reads.
    pub fn gossip_fanout_for_listen_server(&self) -> i64 {
        if self.gossip_fanout == GOSSIP_FANOUT.at(LATEST_VERSION) {
            DEFAULT_RELAY_GOSSIP_FANOUT
        } else {
            self.gossip_fanout
        }
    }
}

/// Go: `defaultRelayGossipFanout` (`config/config.go:88`) — the gossip
/// fanout `enrichNetworkingConfig` substitutes for a listen-server node
/// whose `GossipFanout` wasn't explicitly overridden away from the ordinary
/// default. See [`Local::gossip_fanout_for_listen_server`].
pub const DEFAULT_RELAY_GOSSIP_FANOUT: i64 = 8;

/// Go's `CatchpointTrackingModeUntracked` (`config/config.go:91`): never
/// track or store catchpoints, regardless of `CatchpointInterval`.
pub const CATCHPOINT_TRACKING_MODE_UNTRACKED: i64 = -1;
/// Go's `CatchpointTrackingModeAutomatic` (`config/config.go:95`, the
/// default): archival nodes store catchpoints, non-archival nodes don't.
pub const CATCHPOINT_TRACKING_MODE_AUTOMATIC: i64 = 0;
/// Go's `CatchpointTrackingModeTracked` (`config/config.go:99`): same
/// storage gate as Automatic (archival-only), but always tracks.
pub const CATCHPOINT_TRACKING_MODE_TRACKED: i64 = 1;
/// Go's `CatchpointTrackingModeStored` (`config/config.go:103`): always
/// store catchpoint files, regardless of `Archival`.
pub const CATCHPOINT_TRACKING_MODE_STORED: i64 = 2;

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
            CATCHPOINT_DIR.max_tag_version(),
            STATEPROOF_DIR.max_tag_version(),
            HOT_DATA_DIR.max_tag_version(),
            COLD_DATA_DIR.max_tag_version(),
            TRACKER_DB_DIR.max_tag_version(),
            BLOCK_DB_DIR.max_tag_version(),
            CRASH_DB_DIR.max_tag_version(),
            LOG_FILE_DIR.max_tag_version(),
            LOG_ARCHIVE_DIR.max_tag_version(),
            CATCHPOINT_INTERVAL.max_tag_version(),
            CATCHPOINT_FILE_HISTORY_LENGTH.max_tag_version(),
            CATCHPOINT_TRACKING.max_tag_version(),
            OPTIMIZE_ACCOUNTS_DATABASE_ON_STARTUP.max_tag_version(),
            LEDGER_SYNCHRONOUS_MODE.max_tag_version(),
            ACCOUNTS_REBUILD_SYNCHRONOUS_MODE.max_tag_version(),
            MAX_CATCHPOINT_DOWNLOAD_DURATION.max_tag_version(),
            MIN_CATCHPOINT_FILE_DOWNLOAD_BYTES_PER_SECOND.max_tag_version(),
            DISABLE_LEDGER_LRU_CACHE.max_tag_version(),
            ENDPOINT_ADDRESS.max_tag_version(),
            REST_READ_TIMEOUT_SECONDS.max_tag_version(),
            REST_WRITE_TIMEOUT_SECONDS.max_tag_version(),
            ENABLE_PRIVATE_NETWORK_ACCESS_HEADER.max_tag_version(),
            REST_CONNECTIONS_SOFT_LIMIT.max_tag_version(),
            REST_CONNECTIONS_HARD_LIMIT.max_tag_version(),
            MAX_API_RESOURCES_PER_ACCOUNT.max_tag_version(),
            ENABLE_USAGE_LOG.max_tag_version(),
            MAX_API_BOX_PER_APPLICATION.max_tag_version(),
            TX_INCOMING_FILTERING_FLAGS.max_tag_version(),
            ENABLE_EXPERIMENTAL_API.max_tag_version(),
            ENABLE_FOLLOW_MODE.max_tag_version(),
            ENABLE_TXN_EVAL_TRACER.max_tag_version(),
            TX_INCOMING_FILTER_MAX_SIZE.max_tag_version(),
            ENABLE_DEVELOPER_API.max_tag_version(),
            CATCHUP_PARALLEL_BLOCKS.max_tag_version(),
            CATCHUP_FAILURE_PEER_REFRESH_RATE.max_tag_version(),
            CATCHUP_HTTP_BLOCK_FETCH_TIMEOUT_SEC.max_tag_version(),
            CATCHUP_GOSSIP_BLOCK_FETCH_TIMEOUT_SEC.max_tag_version(),
            CATCHUP_LEDGER_DOWNLOAD_RETRY_ATTEMPTS.max_tag_version(),
            CATCHUP_BLOCK_DOWNLOAD_RETRY_ATTEMPTS.max_tag_version(),
            TX_SYNC_TIMEOUT_SECONDS.max_tag_version(),
            TX_SYNC_INTERVAL_SECONDS.max_tag_version(),
            TX_SYNC_SERVE_RESPONSE_SIZE.max_tag_version(),
            ENABLE_ASSEMBLE_STATS.max_tag_version(),
            ENABLE_PROCESS_BLOCK_STATS.max_tag_version(),
            MAX_BLOCK_HISTORY_LOOKBACK.max_tag_version(),
            PUBLIC_ADDRESS.max_tag_version(),
            P2P_HYBRID_NET_ADDRESS.max_tag_version(),
            ANNOUNCE_PARTICIPATION_KEY.max_tag_version(),
            PRIORITY_PEERS.max_tag_version(),
            RESERVED_FDS.max_tag_version(),
            INCOMING_MESSAGE_FILTER_BUCKET_COUNT.max_tag_version(),
            INCOMING_MESSAGE_FILTER_BUCKET_SIZE.max_tag_version(),
            OUTGOING_MESSAGE_FILTER_BUCKET_COUNT.max_tag_version(),
            OUTGOING_MESSAGE_FILTER_BUCKET_SIZE.max_tag_version(),
            ENABLE_OUTGOING_NETWORK_MESSAGE_FILTERING.max_tag_version(),
            ENABLE_INCOMING_MESSAGE_FILTER.max_tag_version(),
            DNS_SECURITY_FLAGS.max_tag_version(),
            NETWORK_PROTOCOL_VERSION.max_tag_version(),
            USE_X_FORWARDED_FOR_ADDRESS_FIELD.max_tag_version(),
            DISABLE_OUTGOING_CONNECTION_THROTTLING.max_tag_version(),
            DISABLE_LOCALHOST_CONNECTION_RATE_LIMIT.max_tag_version(),
            BLOCK_SERVICE_CUSTOM_FALLBACK_ENDPOINTS.max_tag_version(),
            ENABLE_REQUEST_LOGGER.max_tag_version(),
            FALLBACK_DNS_RESOLVER_ADDRESS.max_tag_version(),
            P2P_PRIVATE_KEY_LOCATION.max_tag_version(),
            ENABLE_DHT_PROVIDERS.max_tag_version(),
            DHT_MODE.max_tag_version(),
            ARCHIVAL.max_tag_version(),
            ENABLE_RUNTIME_METRICS.max_tag_version(),
            ENABLE_NET_DEV_METRICS.max_tag_version(),
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
        assert_eq!(d.catchpoint_dir, "");
        assert_eq!(d.stateproof_dir, "");
        assert_eq!(d.hot_data_dir, "");
        assert_eq!(d.cold_data_dir, "");
        assert_eq!(d.tracker_db_dir, "");
        assert_eq!(d.block_db_dir, "");
        assert_eq!(d.crash_db_dir, "");
        assert_eq!(d.log_file_dir, "");
        assert_eq!(d.log_archive_dir, "");
        assert_eq!(d.catchpoint_interval, 10_000);
        assert_eq!(d.catchpoint_file_history_length, 365);
        assert_eq!(d.catchpoint_tracking, 0);
        assert!(!d.archival, "go's default is false");
        assert!(!d.optimize_accounts_database_on_startup);
        assert_eq!(d.ledger_synchronous_mode, 2, "go's default is FULL(2)");
        assert_eq!(
            d.accounts_rebuild_synchronous_mode, 1,
            "go's default is NORMAL(1)"
        );
        assert_eq!(
            d.max_catchpoint_download_duration, 43_200_000_000_000,
            "go's post-version-28 default (12h in ns), not the pre-28 2h value"
        );
        assert_eq!(d.min_catchpoint_file_download_bytes_per_second, 20_480);
        assert!(!d.disable_ledger_lru_cache);
        assert_eq!(d.endpoint_address, "127.0.0.1:0");
        assert_eq!(d.rest_read_timeout_seconds, 15);
        assert_eq!(d.rest_write_timeout_seconds, 120);
        assert!(!d.enable_private_network_access_header);
        assert_eq!(d.rest_connections_soft_limit, 1024);
        assert_eq!(d.rest_connections_hard_limit, 2048);
        assert_eq!(d.max_api_resources_per_account, 100_000);
        assert!(!d.enable_usage_log);
        assert_eq!(d.max_api_box_per_application, 100_000);
        assert_eq!(d.tx_incoming_filtering_flags, 1);
        assert!(!d.enable_experimental_api);
        assert!(!d.enable_follow_mode);
        assert!(!d.enable_txn_eval_tracer);
        assert_eq!(d.tx_incoming_filter_max_size, 500_000);
        assert!(!d.enable_developer_api);
        assert_eq!(
            d.catchup_parallel_blocks, 16,
            "go's v5 default (16), not the pre-version-5 value of 50"
        );
        assert_eq!(d.catchup_failure_peer_refresh_rate, 10);
        assert_eq!(d.catchup_http_block_fetch_timeout_sec, 4);
        assert_eq!(d.catchup_gossip_block_fetch_timeout_sec, 4);
        assert_eq!(d.catchup_ledger_download_retry_attempts, 50);
        assert_eq!(d.catchup_block_download_retry_attempts, 1_000);
        assert_eq!(d.tx_sync_timeout_seconds, 30);
        assert_eq!(d.tx_sync_interval_seconds, 60);
        assert_eq!(d.tx_sync_serve_response_size, 1_000_000);
        assert_eq!(d.tx_backlog_service_rate_window_seconds, 10);
        assert_eq!(d.tx_backlog_app_tx_rate_limiter_max_size, 1_048_576);
        assert_eq!(d.tx_backlog_app_tx_per_second_rate, 100);
        assert_eq!(d.tx_backlog_app_rate_limiting_congestion_pct, 10);
        assert!(d.enable_tx_backlog_app_rate_limiting);
        assert!(!d.enable_assemble_stats);
        assert!(!d.enable_process_block_stats);
        assert_eq!(d.max_block_history_lookback, 0);
        assert_eq!(d.agreement_incoming_votes_queue_length, 20_000);
        assert_eq!(d.agreement_incoming_proposals_queue_length, 50);
        assert_eq!(d.agreement_incoming_bundles_queue_length, 15);
        assert_eq!(d.max_acct_lookback, 4);
        assert!(!d.enable_agreement_reporting);
        assert!(!d.enable_agreement_time_metrics);
        assert_eq!(d.public_address, "");
        assert_eq!(d.p2p_hybrid_net_address, "");
        assert!(d.announce_participation_key);
        assert!(d.priority_peers.is_empty());
        assert_eq!(d.reserved_fds, 256);
        assert_eq!(d.incoming_message_filter_bucket_count, 5);
        assert_eq!(d.incoming_message_filter_bucket_size, 512);
        assert_eq!(d.outgoing_message_filter_bucket_count, 3);
        assert_eq!(d.outgoing_message_filter_bucket_size, 128);
        assert!(d.enable_outgoing_network_message_filtering);
        assert!(!d.enable_incoming_message_filter);
        assert_eq!(d.dns_security_flags, 9, "go's post-version-34 default (9)");
        assert_eq!(d.network_protocol_version, "");
        assert_eq!(d.use_x_forwarded_for_address_field, "");
        assert!(!d.disable_outgoing_connection_throttling);
        assert!(
            d.disable_localhost_connection_rate_limit,
            "go's real default is true (localhost is exempt by default)"
        );
        assert_eq!(d.block_service_custom_fallback_endpoints, "");
        assert!(!d.enable_request_logger);
        assert_eq!(d.fallback_dns_resolver_address, "");
        assert_eq!(d.p2p_private_key_location, "");
        assert!(!d.enable_dht_providers);
        assert_eq!(d.dht_mode, "");
        assert!(!d.enable_runtime_metrics);
        assert!(!d.enable_netdev_metrics);
    }

    // --- Remaining networking fields (issue #768) ------------------------

    #[test]
    fn priority_peers_round_trips_as_map() {
        let cfg = Local::load_from_str(
            r#"{"PriorityPeers": {"10.0.0.1:4160": true, "10.0.0.2:4160": false}}"#,
        )
        .expect("parses");
        assert_eq!(cfg.priority_peers.len(), 2);
        assert_eq!(cfg.priority_peers.get("10.0.0.1:4160"), Some(&true));
        assert_eq!(cfg.priority_peers.get("10.0.0.2:4160"), Some(&false));

        // Round-trip through save/load.
        let json = cfg.to_json_minimized().expect("serializes");
        let reloaded = Local::load_from_str(&json).expect("reparses");
        assert_eq!(reloaded.priority_peers, cfg.priority_peers);
    }

    #[test]
    fn priority_peers_defaults_to_empty_map() {
        assert!(Local::default().priority_peers.is_empty());
        assert!(Local::default_at_version(0).priority_peers.is_empty());
    }

    #[test]
    fn message_filter_fields_partial_overlay() {
        let cfg = Local::load_from_str(
            r#"{"IncomingMessageFilterBucketCount": 7, "OutgoingMessageFilterBucketSize": 64,
                "EnableIncomingMessageFilter": true}"#,
        )
        .expect("parses");
        assert_eq!(cfg.incoming_message_filter_bucket_count, 7);
        assert_eq!(cfg.outgoing_message_filter_bucket_size, 64);
        assert!(cfg.enable_incoming_message_filter);
        // Untouched fields keep their defaults.
        assert_eq!(cfg.incoming_message_filter_bucket_size, 512);
        assert_eq!(cfg.outgoing_message_filter_bucket_count, 3);
        assert!(cfg.enable_outgoing_network_message_filtering);
    }

    #[test]
    fn dns_security_flags_migrates_across_version_34() {
        // A config saved at version 6 (pre-bump) with the field still at
        // its then-current default (1) must advance to the new default (9)
        // when migrated forward — the operator never explicitly overrode
        // it away from the old default.
        let mut cfg = Local::default_at_version(6);
        assert_eq!(cfg.dns_security_flags, 1);
        cfg.migrate().expect("migrates");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(cfg.dns_security_flags, 9);
    }

    #[test]
    fn dns_security_flags_explicit_override_survives_migration() {
        // An operator who explicitly set a custom flags value keeps it
        // across the version-34 bump, mirroring migrate_field's
        // "still equal to old default" guard.
        let mut cfg = Local::default_at_version(6);
        cfg.dns_security_flags = 3; // explicit override, not the v6 default of 1
        cfg.migrate().expect("migrates");
        assert_eq!(cfg.dns_security_flags, 3);
    }

    #[test]
    fn disable_localhost_connection_rate_limit_defaults_true() {
        assert!(Local::default().disable_localhost_connection_rate_limit);
        // Pin `Version` to the latest so `migrate()` is a no-op and the
        // explicit override below isn't reinterpreted as "still at the
        // pre-version-16 zero-value default" (which — like any bool
        // field explicitly set to `false` under an unversioned/`0`
        // config — would otherwise get advanced back to `true` by
        // `migrate_field`'s old-default equality check; see
        // `field_at_default_that_happens_to_match_a_later_versions_default_still_advances`
        // for that documented, go-matching quirk).
        let cfg = Local::load_from_str(
            r#"{"Version": 38, "DisableLocalhostConnectionRateLimit": false}"#,
        )
        .expect("parses");
        assert!(!cfg.disable_localhost_connection_rate_limit);
    }

    #[test]
    fn p2p_private_key_location_round_trip() {
        let cfg =
            Local::load_from_str(r#"{"P2PPrivateKeyLocation": "/data/p2p.key"}"#).expect("parses");
        assert_eq!(cfg.p2p_private_key_location, "/data/p2p.key");
    }

    #[test]
    fn dht_fields_round_trip() {
        let cfg = Local::load_from_str(r#"{"EnableDHTProviders": true, "DHTMode": "server"}"#)
            .expect("parses");
        assert!(cfg.enable_dht_providers);
        assert_eq!(cfg.dht_mode, "server");
    }

    /// Issue #776: `EnableRuntimeMetrics`/`EnableNetDevMetrics` default to
    /// `false` (matching go) and round-trip through `config.json` overlay
    /// independently of each other.
    #[test]
    fn enable_runtime_and_netdev_metrics_default_false_and_overlay() {
        let d = Local::default();
        assert!(!d.enable_runtime_metrics, "go's default is false");
        assert!(!d.enable_netdev_metrics, "go's default is false");

        let cfg = Local::load_from_str(r#"{"EnableRuntimeMetrics": true}"#).expect("parses");
        assert!(cfg.enable_runtime_metrics);
        assert!(
            !cfg.enable_netdev_metrics,
            "untouched field keeps its default"
        );

        let cfg = Local::load_from_str(r#"{"EnableNetDevMetrics": true}"#).expect("parses");
        assert!(!cfg.enable_runtime_metrics);
        assert!(cfg.enable_netdev_metrics);
    }

    /// `EnableRuntimeMetrics` carries `version[22]`: a config loaded at a
    /// pre-22 version must still migrate it to `false` once it reaches
    /// version 22, and an explicit operator override must survive the
    /// migration walk (mirrors the same guarantee tested elsewhere for
    /// `DisableLocalhostConnectionRateLimit`'s version-34 tag).
    #[test]
    fn enable_runtime_metrics_migrates_at_version_22_boundary() {
        let mut cfg = Local::load_from_str(r#"{"Version": 21}"#).expect("parses");
        assert!(!cfg.enable_runtime_metrics);
        cfg.migrate().expect("migrates");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert!(
            !cfg.enable_runtime_metrics,
            "tag default is false; migrating past version 22 changes nothing observable here"
        );
    }

    /// `EnableNetDevMetrics` carries `version[34]`: an explicit override set
    /// on an old-versioned config must survive migration all the way to
    /// [`LATEST_VERSION`].
    #[test]
    fn enable_netdev_metrics_override_survives_migration_past_version_34() {
        let mut cfg = Local::load_from_str(r#"{"Version": 30, "EnableNetDevMetrics": true}"#)
            .expect("parses");
        cfg.migrate().expect("migrates");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert!(
            cfg.enable_netdev_metrics,
            "explicit override must not be clobbered by the version-34 tag's default"
        );
    }

    #[test]
    fn vote_compression_and_batch_verification_fields_are_not_present() {
        // Explicitly asserts issue #768's disposition: these upstream
        // fields must NOT exist on `Local` at all (no-op knobs for
        // nonexistent features are worse than no knob). Encoded as a
        // negative JSON-shape check so a future accidental re-add is
        // caught: `serde` would otherwise silently accept and drop an
        // unknown field, so this only guards the "someone adds it as a
        // real field" case together with the source-level absence, which
        // is the actual contract here.
        let default_json = Local::default().to_json_full().expect("serializes");
        assert!(!default_json.contains("EnableVoteCompression"));
        assert!(!default_json.contains("StatefulVoteCompressionTableSize"));
        assert!(!default_json.contains("EnableBatchVerification"));
    }

    // --- Catchup/sync fields (issue #753) --------------------------------

    #[test]
    fn catchup_parallel_blocks_defaults_to_v5_value_and_overlays() {
        assert_eq!(Local::default().catchup_parallel_blocks, 16);
        let cfg = Local::load_from_str(r#"{"CatchupParallelBlocks": 4}"#).expect("parses");
        assert_eq!(cfg.catchup_parallel_blocks, 4);
    }

    #[test]
    fn catchup_timeouts_and_retry_attempts_partial_overlay() {
        let cfg = Local::load_from_str(
            r#"{"CatchupHTTPBlockFetchTimeoutSec": 8, "CatchupBlockDownloadRetryAttempts": 5}"#,
        )
        .expect("parses");
        assert_eq!(cfg.catchup_http_block_fetch_timeout_sec, 8);
        assert_eq!(cfg.catchup_block_download_retry_attempts, 5);
        assert_eq!(
            cfg.catchup_gossip_block_fetch_timeout_sec, 4,
            "untouched field keeps its default"
        );
        assert_eq!(
            cfg.catchup_ledger_download_retry_attempts, 50,
            "untouched field keeps its default"
        );
        assert_eq!(cfg.catchup_failure_peer_refresh_rate, 10);
    }

    #[test]
    fn tx_sync_fields_round_trip_and_overlay() {
        let cfg = Local::load_from_str(
            r#"{"TxSyncTimeoutSeconds": 5, "TxSyncIntervalSeconds": 15, "TxSyncServeResponseSize": 2000}"#,
        )
        .expect("parses");
        assert_eq!(cfg.tx_sync_timeout_seconds, 5);
        assert_eq!(cfg.tx_sync_interval_seconds, 15);
        assert_eq!(cfg.tx_sync_serve_response_size, 2000);
    }

    #[test]
    fn assemble_and_process_block_stats_and_max_block_history_lookback_round_trip() {
        let cfg = Local::load_from_str(
            r#"{"EnableAssembleStats": true, "EnableProcessBlockStats": true, "MaxBlockHistoryLookback": 1000}"#,
        )
        .expect("parses");
        assert!(cfg.enable_assemble_stats);
        assert!(cfg.enable_process_block_stats);
        assert_eq!(cfg.max_block_history_lookback, 1000);
    }

    #[test]
    fn catchup_parallel_blocks_explicit_override_survives_migration() {
        // An operator-chosen value that never matches any version's default
        // (50 and 16 are the only tagged defaults) must survive migration
        // unchanged; a config that never touched the field must instead
        // advance to the new version[5] default of 16.
        let cfg =
            Local::load_from_str(r#"{"Version": 3, "CatchupParallelBlocks": 4}"#).expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(
            cfg.catchup_parallel_blocks, 4,
            "explicit override must survive migration"
        );

        let cfg = Local::load_from_str(r#"{"Version": 3}"#).expect("parses");
        assert_eq!(
            cfg.catchup_parallel_blocks, 16,
            "an untouched field migrates forward to the new default"
        );
    }

    // --- Agreement-protocol fields (issue #755) --------------------------

    #[test]
    fn agreement_queue_lengths_default_to_v27_plus_values_and_overlay() {
        // go's `AgreementIncomingVotesQueueLength`/`...ProposalsQueueLength`/
        // `...BundlesQueueLength` bumped at version 27 to 20000/50/15
        // (`config/localTemplate.go`). At `LATEST_VERSION` (35) the
        // materialized default must be the v27+ value, not the stale
        // pre-v27 one (10000/25/7).
        let d = Local::default();
        assert_eq!(d.agreement_incoming_votes_queue_length, 20_000);
        assert_eq!(d.agreement_incoming_proposals_queue_length, 50);
        assert_eq!(d.agreement_incoming_bundles_queue_length, 15);

        let cfg = Local::load_from_str(
            r#"{"AgreementIncomingVotesQueueLength": 1000, "AgreementIncomingProposalsQueueLength": 5, "AgreementIncomingBundlesQueueLength": 2}"#,
        )
        .expect("parses");
        assert_eq!(cfg.agreement_incoming_votes_queue_length, 1000);
        assert_eq!(cfg.agreement_incoming_proposals_queue_length, 5);
        assert_eq!(cfg.agreement_incoming_bundles_queue_length, 2);
    }

    #[test]
    fn agreement_queue_lengths_explicit_override_survives_migration() {
        // A config pinned at version 21 (pre-bump) that never touched the
        // field must migrate forward to the v27+ default; one that
        // explicitly set the pre-bump value must keep it unchanged.
        let cfg = Local::load_from_str(r#"{"Version": 21}"#).expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(cfg.agreement_incoming_votes_queue_length, 20_000);
        assert_eq!(cfg.agreement_incoming_proposals_queue_length, 50);
        assert_eq!(cfg.agreement_incoming_bundles_queue_length, 15);

        let cfg =
            Local::load_from_str(r#"{"Version": 21, "AgreementIncomingProposalsQueueLength": 99}"#)
                .expect("parses");
        assert_eq!(
            cfg.agreement_incoming_proposals_queue_length, 99,
            "explicit override must survive migration"
        );
    }

    #[test]
    fn max_acct_lookback_defaults_to_go_value_of_4_and_overlays() {
        // Issue #755: algod-rust's actual in-memory delta-cache window
        // (`DeltaCache::DEFAULT_WINDOW_SIZE`) was hardcoded to 320 rounds,
        // 80x go's real `MaxAcctLookback` default of 4
        // (`config/localTemplate.go:563-565`, consumed at
        // `ledger/acctupdates.go:294`). This field now carries the correct
        // go-matching default and is a real configurable knob.
        assert_eq!(Local::default().max_acct_lookback, 4);
        let cfg = Local::load_from_str(r#"{"MaxAcctLookback": 64}"#).expect("parses");
        assert_eq!(cfg.max_acct_lookback, 64);
    }

    #[test]
    fn enable_agreement_reporting_and_time_metrics_default_false_and_overlay() {
        // go: `EnableAgreementReporting`/`EnableAgreementTimeMetrics bool`
        // `version[3]:"false"` (`config/localTemplate.go:219-223`).
        let d = Local::default();
        assert!(!d.enable_agreement_reporting);
        assert!(!d.enable_agreement_time_metrics);

        let cfg = Local::load_from_str(
            r#"{"EnableAgreementReporting": true, "EnableAgreementTimeMetrics": true}"#,
        )
        .expect("parses");
        assert!(cfg.enable_agreement_reporting);
        assert!(cfg.enable_agreement_time_metrics);
    }

    // --- REST/API fields (issue #751) -----------------------------------

    #[test]
    fn endpoint_address_defaults_to_gos_always_on_ephemeral_port() {
        // The headline fix: go's `EndpointAddress` always defaults to
        // "127.0.0.1:0" (REST always starts, on an ephemeral local port).
        // algod-rust's config layer must carry that same default so
        // `RestOptions::resolve` can align with it.
        assert_eq!(Local::default().endpoint_address, "127.0.0.1:0");
        let cfg = Local::load_from_str("{}").expect("parses");
        assert_eq!(cfg.endpoint_address, "127.0.0.1:0");
    }

    #[test]
    fn endpoint_address_explicit_override_survives_migration() {
        let cfg = Local::load_from_str(r#"{"Version": 0, "EndpointAddress": "0.0.0.0:8080"}"#)
            .expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(cfg.endpoint_address, "0.0.0.0:8080");
    }

    #[test]
    fn endpoint_address_explicit_empty_string_is_preserved_as_disable_affordance() {
        // algod-rust treats an explicit empty `EndpointAddress` as "disable
        // REST" (see that field's `VersionedDefault` doc comment) — an
        // explicit override, so migration must never clobber it back to
        // the "127.0.0.1:0" default.
        let cfg = Local::load_from_str(r#"{"Version": 0, "EndpointAddress": ""}"#).expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(cfg.endpoint_address, "");
    }

    #[test]
    fn rest_timeouts_partial_overlay() {
        let cfg = Local::load_from_str(r#"{"RestReadTimeoutSeconds": 5}"#).expect("parses");
        assert_eq!(cfg.rest_read_timeout_seconds, 5);
        assert_eq!(
            cfg.rest_write_timeout_seconds, 120,
            "untouched field keeps its default"
        );
    }

    #[test]
    fn rest_connections_limits_partial_overlay() {
        let cfg = Local::load_from_str(r#"{"RestConnectionsSoftLimit": 10}"#).expect("parses");
        assert_eq!(cfg.rest_connections_soft_limit, 10);
        assert_eq!(cfg.rest_connections_hard_limit, 2048);
    }

    #[test]
    fn max_api_resources_and_boxes_partial_overlay() {
        let cfg = Local::load_from_str(
            r#"{"MaxAPIResourcesPerAccount": 5, "MaxAPIBoxPerApplication": 7}"#,
        )
        .expect("parses");
        assert_eq!(cfg.max_api_resources_per_account, 5);
        assert_eq!(cfg.max_api_box_per_application, 7);
    }

    #[test]
    fn enable_developer_api_and_experimental_api_default_false_and_overlay() {
        let cfg = Local::default();
        assert!(!cfg.enable_developer_api, "go's default is false");
        assert!(!cfg.enable_experimental_api, "go's default is false");
        let cfg =
            Local::load_from_str(r#"{"EnableDeveloperAPI": true, "EnableExperimentalAPI": true}"#)
                .expect("parses");
        assert!(cfg.enable_developer_api);
        assert!(cfg.enable_experimental_api);
    }

    #[test]
    fn enable_follow_mode_and_txn_eval_tracer_and_usage_log_round_trip() {
        let cfg = Local::load_from_str(
            r#"{"EnableFollowMode": true, "EnableTxnEvalTracer": true, "EnableUsageLog": true}"#,
        )
        .expect("parses");
        assert!(cfg.enable_follow_mode);
        assert!(cfg.enable_txn_eval_tracer);
        assert!(cfg.enable_usage_log);
    }

    #[test]
    fn tx_incoming_filter_fields_round_trip() {
        let cfg = Local::load_from_str(
            r#"{"TxIncomingFilteringFlags": 3, "TxIncomingFilterMaxSize": 42}"#,
        )
        .expect("parses");
        assert_eq!(cfg.tx_incoming_filtering_flags, 3);
        assert_eq!(cfg.tx_incoming_filter_max_size, 42);
    }

    #[test]
    fn enable_private_network_access_header_round_trip() {
        let cfg =
            Local::load_from_str(r#"{"EnablePrivateNetworkAccessHeader": true}"#).expect("parses");
        assert!(cfg.enable_private_network_access_header);
    }

    #[test]
    fn max_catchpoint_download_duration_migrates_from_2h_to_12h_default() {
        // A config.json written before version 28, left at version 13's own
        // default (2h in ns) — i.e. never touched by the operator — must
        // advance to version 28's 12h default across migration.
        let cfg = Local::load_from_str(
            r#"{"Version": 13, "MaxCatchpointDownloadDuration": 7200000000000}"#,
        )
        .expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(cfg.max_catchpoint_download_duration, 43_200_000_000_000);
    }

    #[test]
    fn max_catchpoint_download_duration_explicit_override_survives_migration() {
        let cfg = Local::load_from_str(
            r#"{"Version": 13, "MaxCatchpointDownloadDuration": 999000000000}"#,
        )
        .expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(
            cfg.max_catchpoint_download_duration, 999_000_000_000,
            "an explicit non-default override must survive migration"
        );
    }

    #[test]
    fn catchpoint_dir_and_stateproof_dir_round_trip_through_json() {
        let cfg = Local::load_from_str(
            r#"{"CatchpointDir": "/data/catchpoints", "StateproofDir": "/data/stateproof"}"#,
        )
        .expect("parses");
        assert_eq!(cfg.catchpoint_dir, "/data/catchpoints");
        assert_eq!(cfg.stateproof_dir, "/data/stateproof");
    }

    /// TDD anchor for issue #953: the hot/cold/per-resource data-dir
    /// override fields must round-trip through `config.json` (partial
    /// overlay — only the fields present in the JSON change; the rest keep
    /// their empty-string default), matching go's `HotDataDir`/
    /// `ColdDataDir`/`TrackerDBDir`/`BlockDBDir`/`CrashDBDir`
    /// (`../go-algorand/config/localTemplate.go:93-122`).
    #[test]
    fn resource_data_dirs_round_trip_through_json() {
        let cfg = Local::load_from_str(
            r#"{
                "HotDataDir": "/data/hot",
                "ColdDataDir": "/data/cold",
                "TrackerDBDir": "/data/hot/tracker",
                "BlockDBDir": "/data/cold/block",
                "CrashDBDir": "/data/hot/crash"
            }"#,
        )
        .expect("parses");
        assert_eq!(cfg.hot_data_dir, "/data/hot");
        assert_eq!(cfg.cold_data_dir, "/data/cold");
        assert_eq!(cfg.tracker_db_dir, "/data/hot/tracker");
        assert_eq!(cfg.block_db_dir, "/data/cold/block");
        assert_eq!(cfg.crash_db_dir, "/data/hot/crash");
        // Fields not present in the JSON keep their empty-string default.
        assert_eq!(cfg.log_file_dir, "");
        assert_eq!(cfg.log_archive_dir, "");
    }

    #[test]
    fn disable_ledger_lru_cache_partial_overlay() {
        let cfg = Local::load_from_str(r#"{"DisableLedgerLRUCache": true}"#).expect("parses");
        assert!(cfg.disable_ledger_lru_cache);
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

    // --- Logging / telemetry / profiling fields (issue #756) ---------------

    #[test]
    fn base_logger_debug_level_migrates_from_1_to_4_default() {
        // Left at version 0's own default (1 = Fatal), never touched by the
        // operator, must advance to version 1's default (4 = Info).
        let cfg =
            Local::load_from_str(r#"{"Version": 0, "BaseLoggerDebugLevel": 1}"#).expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(cfg.base_logger_debug_level, 4);
    }

    #[test]
    fn base_logger_debug_level_explicit_override_survives_migration() {
        let cfg =
            Local::load_from_str(r#"{"Version": 0, "BaseLoggerDebugLevel": 5}"#).expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(
            cfg.base_logger_debug_level, 5,
            "an explicit non-default override must survive migration"
        );
    }

    #[test]
    fn base_logger_debug_level_to_filter_directive_covers_gos_full_range() {
        assert_eq!(base_logger_debug_level_to_filter_directive(0), "error"); // Panic
        assert_eq!(base_logger_debug_level_to_filter_directive(1), "error"); // Fatal
        assert_eq!(base_logger_debug_level_to_filter_directive(2), "error"); // Error
        assert_eq!(base_logger_debug_level_to_filter_directive(3), "warn"); // Warn
        assert_eq!(base_logger_debug_level_to_filter_directive(4), "info"); // Info
        assert_eq!(base_logger_debug_level_to_filter_directive(5), "debug"); // Debug
        assert_eq!(
            base_logger_debug_level_to_filter_directive(99),
            "debug",
            "out-of-range levels fall back to the most verbose directive, not a panic"
        );
    }

    #[test]
    fn cadaver_size_target_migrates_from_1gib_to_disabled_default() {
        // Left at version 0's own default (1 GiB), never touched by the
        // operator, must advance to version 24's default (0 = disabled).
        let cfg = Local::load_from_str(r#"{"Version": 0, "CadaverSizeTarget": 1073741824}"#)
            .expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(cfg.cadaver_size_target, 0);
    }

    #[test]
    fn cadaver_size_target_explicit_override_survives_migration() {
        let cfg = Local::load_from_str(r#"{"Version": 0, "CadaverSizeTarget": 209715200}"#)
            .expect("parses");
        assert_eq!(cfg.version, LATEST_VERSION);
        assert_eq!(
            cfg.cadaver_size_target, 209_715_200,
            "an explicit non-default override must survive migration"
        );
    }

    #[test]
    fn cadaver_directory_round_trips_through_json() {
        let cfg = Local::load_from_str(r#"{"CadaverDirectory": "/data/cadaver"}"#).expect("parses");
        assert_eq!(cfg.cadaver_directory, "/data/cadaver");
    }

    #[test]
    fn telemetry_to_log_defaults_true_and_round_trips() {
        assert!(Local::default().telemetry_to_log);
        // Pin `Version` at LATEST_VERSION so migration is a no-op: an
        // override to `false` (this field's pre-tag zero value) written at
        // an earlier version would be indistinguishable from "never set"
        // and get advanced back to the post-tag `true` default by
        // `migrate_field` -- exactly mirroring go's own
        // `reflect.DeepEqual`-based ambiguity for a bool field whose
        // explicit override equals its untagged zero value. Only
        // migration-preservation tests need to exercise that boundary
        // (see `field_explicitly_overridden_away_from_default_is_never_clobbered`);
        // this test is just pinning the plain JSON round-trip.
        let cfg =
            Local::load_from_str(r#"{"Version": 35, "TelemetryToLog": false}"#).expect("parses");
        assert!(!cfg.telemetry_to_log);
    }

    #[test]
    fn log_rotation_fields_round_trip_through_json() {
        let cfg = Local::load_from_str(
            r#"{"LogSizeLimit": 500000, "LogArchiveName": "custom.archive.log", "LogArchiveMaxAge": "168h"}"#,
        )
        .expect("parses");
        assert_eq!(cfg.log_size_limit, 500_000);
        assert_eq!(cfg.log_archive_name, "custom.archive.log");
        assert_eq!(cfg.log_archive_max_age, "168h");
        // Defaults match go's `local_defaults.go`.
        let default_cfg = Local::default();
        assert_eq!(default_cfg.log_size_limit, 1_073_741_824);
        assert_eq!(default_cfg.log_archive_name, "node.archive.log");
        assert_eq!(default_cfg.log_archive_max_age, "");
    }

    #[test]
    fn enable_profiler_round_trip() {
        assert!(!Local::default().enable_profiler);
        let cfg = Local::load_from_str(r#"{"EnableProfiler": true}"#).expect("parses");
        assert!(cfg.enable_profiler);
    }

    #[test]
    fn enable_top_accounts_reporting_round_trip_default_false() {
        assert!(!Local::default().enable_top_accounts_reporting);
        let cfg = Local::load_from_str(r#"{"EnableTopAccountsReporting": true}"#).expect("parses");
        assert!(cfg.enable_top_accounts_reporting);
    }

    /// Deliberately-excluded telemetry-only fields (`PeerConnectionsUpdateInterval`,
    /// `HeartbeatUpdateInterval`, `EnableAccountUpdatesStats`,
    /// `AccountUpdatesStatsInterval`) must NOT round-trip through
    /// `config.json` — an operator's file setting these keys should not
    /// silently be accepted as if they had an effect, so an unknown-field
    /// parse must not error (`serde_json` ignores unknown fields by
    /// default) but the resulting `Local` must carry no field for them.
    /// This test pins that "present in JSON, absent from `Local`" shape by
    /// asserting the config still parses and the known-fields set is
    /// otherwise unaffected.
    #[test]
    fn telemetry_only_fields_are_accepted_but_ignored_not_modeled() {
        let cfg = Local::load_from_str(
            r#"{"PeerConnectionsUpdateInterval": 60, "HeartbeatUpdateInterval": 30, "EnableAccountUpdatesStats": true, "AccountUpdatesStatsInterval": 1}"#,
        )
        .expect("unknown JSON keys are ignored, not rejected");
        // Nothing to assert on the ignored keys themselves (they have no
        // field) -- confirm the rest of the config still loaded at its
        // ordinary defaults, i.e. parsing wasn't otherwise disrupted.
        assert_eq!(cfg, Local::default());
    }

    // -----------------------------------------------------------------
    // Issue #770: `stores_catchpoints`/`tracks_catchpoints` mode
    // resolution, mirroring go's `config_test.go`
    // `TestStoresCatchpoints`/`TestTracksCatchpointsWithoutStoring`.
    // -----------------------------------------------------------------

    /// `CatchpointInterval == 0` disables catchpoint generation
    /// regardless of `CatchpointTracking` or `Archival` -- go's
    /// `cfg.CatchpointInterval <= 0` short-circuit.
    #[test]
    fn stores_catchpoints_false_when_interval_is_zero() {
        for tracking in [
            CATCHPOINT_TRACKING_MODE_UNTRACKED,
            CATCHPOINT_TRACKING_MODE_AUTOMATIC,
            CATCHPOINT_TRACKING_MODE_TRACKED,
            CATCHPOINT_TRACKING_MODE_STORED,
        ] {
            let cfg = Local {
                catchpoint_interval: 0,
                catchpoint_tracking: tracking,
                archival: true,
                ..Local::default()
            };
            assert!(
                !cfg.stores_catchpoints(),
                "tracking={tracking} must not store when interval is 0"
            );
        }
    }

    /// `CatchpointTrackingModeUntracked` (-1) never stores, even on an
    /// archival node with a positive interval.
    #[test]
    fn stores_catchpoints_false_for_untracked_mode() {
        let cfg = Local {
            catchpoint_interval: 10_000,
            catchpoint_tracking: CATCHPOINT_TRACKING_MODE_UNTRACKED,
            archival: true,
            ..Local::default()
        };
        assert!(!cfg.stores_catchpoints());
    }

    /// `CatchpointTrackingModeStored` (2) always stores when interval > 0,
    /// regardless of `Archival`.
    #[test]
    fn stores_catchpoints_true_for_stored_mode_regardless_of_archival() {
        for archival in [false, true] {
            let cfg = Local {
                catchpoint_interval: 10_000,
                catchpoint_tracking: CATCHPOINT_TRACKING_MODE_STORED,
                archival,
                ..Local::default()
            };
            assert!(
                cfg.stores_catchpoints(),
                "Stored mode must store regardless of archival={archival}"
            );
        }
    }

    /// `CatchpointTrackingModeAutomatic` (0, the default) and
    /// `CatchpointTrackingModeTracked` (1) both gate on `Archival`: store
    /// only when the node is archival.
    #[test]
    fn stores_catchpoints_automatic_and_tracked_modes_gate_on_archival() {
        for tracking in [
            CATCHPOINT_TRACKING_MODE_AUTOMATIC,
            CATCHPOINT_TRACKING_MODE_TRACKED,
        ] {
            let non_archival = Local {
                catchpoint_interval: 10_000,
                catchpoint_tracking: tracking,
                archival: false,
                ..Local::default()
            };
            assert!(
                !non_archival.stores_catchpoints(),
                "tracking={tracking} on a non-archival node must not store"
            );

            let archival = Local {
                catchpoint_interval: 10_000,
                catchpoint_tracking: tracking,
                archival: true,
                ..Local::default()
            };
            assert!(
                archival.stores_catchpoints(),
                "tracking={tracking} on an archival node must store"
            );
        }
    }

    /// A stock default config (`CatchpointTracking = 0`, `Archival =
    /// false`, `CatchpointInterval = 10_000`) must NOT auto-generate
    /// catchpoints -- exactly matching a stock non-archival go-algorand
    /// node, even though `CatchpointInterval` is positive.
    #[test]
    fn stores_catchpoints_false_for_stock_default_config() {
        assert!(!Local::default().stores_catchpoints());
    }

    /// An unrecognized `CatchpointTracking` value falls through to the
    /// same archival-gated behavior as Automatic/Tracked -- go's `switch`
    /// has a `default: fallthrough` case into exactly that arm.
    #[test]
    fn stores_catchpoints_unrecognized_tracking_value_falls_through_to_archival_gate() {
        let non_archival = Local {
            catchpoint_interval: 10_000,
            catchpoint_tracking: 99,
            archival: false,
            ..Local::default()
        };
        assert!(!non_archival.stores_catchpoints());

        let archival = Local {
            catchpoint_interval: 10_000,
            catchpoint_tracking: 99,
            archival: true,
            ..Local::default()
        };
        assert!(archival.stores_catchpoints());
    }

    /// `tracks_catchpoints` is a superset of `stores_catchpoints`: Tracked
    /// mode on a non-archival node tracks without storing.
    #[test]
    fn tracks_catchpoints_true_for_tracked_mode_without_storing() {
        let cfg = Local {
            catchpoint_interval: 10_000,
            catchpoint_tracking: CATCHPOINT_TRACKING_MODE_TRACKED,
            archival: false,
            ..Local::default()
        };
        assert!(!cfg.stores_catchpoints());
        assert!(cfg.tracks_catchpoints());
    }

    /// `tracks_catchpoints` is false when neither storing nor Tracked mode
    /// applies.
    #[test]
    fn tracks_catchpoints_false_when_untracked() {
        let cfg = Local {
            catchpoint_interval: 10_000,
            catchpoint_tracking: CATCHPOINT_TRACKING_MODE_UNTRACKED,
            archival: false,
            ..Local::default()
        };
        assert!(!cfg.tracks_catchpoints());
    }

    // --- `gossip_fanout_for_listen_server` (issue #788) --------------------
    //
    // Go: `enrichNetworkingConfig` (`config/config.go:170-179`) substitutes
    // `defaultRelayGossipFanout` (8) for a listen-server node's
    // `GossipFanout` unless the operator already overrode it away from the
    // ordinary default (4).

    /// A default (un-overridden) `GossipFanout` gets bumped to go's
    /// `defaultRelayGossipFanout` (8) for a node known to be a listen
    /// server.
    #[test]
    fn gossip_fanout_for_listen_server_bumps_default_to_relay_fanout() {
        let cfg = Local::default();
        assert_eq!(cfg.gossip_fanout, 4, "precondition: ordinary default is 4");
        assert_eq!(cfg.gossip_fanout_for_listen_server(), 8);
    }

    /// An operator-overridden `GossipFanout` (anything other than the
    /// ordinary default) is left untouched — go's equality check against
    /// `defaultLocal.GossipFanout` is the only gate, not "always bump".
    #[test]
    fn gossip_fanout_for_listen_server_preserves_explicit_override() {
        let cfg = Local {
            gossip_fanout: 20,
            ..Local::default()
        };
        assert_eq!(cfg.gossip_fanout_for_listen_server(), 20);

        // An explicit override *equal to go's relay default* is also just
        // preserved, not doubled or re-derived — it already reads 8.
        let cfg_already_eight = Local {
            gossip_fanout: 8,
            ..Local::default()
        };
        assert_eq!(cfg_already_eight.gossip_fanout_for_listen_server(), 8);
    }

    /// An explicit override of exactly `0` (or negative, which go's `int`
    /// field permits round-tripping through JSON) is still "explicit" —
    /// it must not be confused with "unset" and silently bumped.
    #[test]
    fn gossip_fanout_for_listen_server_preserves_explicit_zero_override() {
        let cfg = Local {
            gossip_fanout: 0,
            ..Local::default()
        };
        assert_eq!(cfg.gossip_fanout_for_listen_server(), 0);
    }
}
