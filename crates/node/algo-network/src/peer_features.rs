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

//! Peer feature negotiation and capability flags.
//!
//! During the WebSocket handshake, peers exchange an `X-Algorand-Peer-Features`
//! header containing a comma-separated list of feature strings.  Each feature
//! string maps to a capability flag that controls protocol behaviour for that
//! connection (e.g., zstd-compressed proposals, vpack-compressed votes).
//!
//! Feature negotiation was introduced in network protocol version `"2.2"`.
//! Peers running older protocol versions ignore the header entirely.
//!
//! # Go reference
//!
//! - `network/wsNetwork.go` — `PeerFeaturesHeader`, feature string constants,
//!   header encoding
//! - `network/wsPeer.go` — `peerFeatureFlag`, `decodePeerFeatures`

// Re-export from handshake module for backward compatibility.
pub use crate::handshake::PEER_FEATURES_HEADER;

/// Minimum network protocol version that supports peer feature negotiation.
///
/// Peers advertising a protocol version earlier than `"2.2"` do not participate
/// in feature negotiation and the header should be ignored even if present.
pub const VERSION_PEER_FEATURES: &str = "2.2";

// ---------------------------------------------------------------------------
// Feature string constants (must match go-algorand exactly)
// ---------------------------------------------------------------------------

/// Proposal payload zstd compression (`ppzstd`).
const FEATURE_STR_PPZSTD: &str = "ppzstd";

/// Stateless agreement vote vpack compression (`avvpack`).
const FEATURE_STR_AVVPACK: &str = "avvpack";

/// Stateful agreement vote vpack compression with table size 2048 (`avvpack2048`).
const FEATURE_STR_AVVPACK2048: &str = "avvpack2048";

/// Stateful agreement vote vpack compression with table size 1024 (`avvpack1024`).
const FEATURE_STR_AVVPACK1024: &str = "avvpack1024";

/// Stateful agreement vote vpack compression with table size 512 (`avvpack512`).
const FEATURE_STR_AVVPACK512: &str = "avvpack512";

/// Stateful agreement vote vpack compression with table size 256 (`avvpack256`).
const FEATURE_STR_AVVPACK256: &str = "avvpack256";

/// Stateful agreement vote vpack compression with table size 128 (`avvpack128`).
const FEATURE_STR_AVVPACK128: &str = "avvpack128";

/// Stateful agreement vote vpack compression with table size 64 (`avvpack64`).
const FEATURE_STR_AVVPACK64: &str = "avvpack64";

/// Stateful agreement vote vpack compression with table size 32 (`avvpack32`).
const FEATURE_STR_AVVPACK32: &str = "avvpack32";

/// Stateful agreement vote vpack compression with table size 16 (`avvpack16`).
const FEATURE_STR_AVVPACK16: &str = "avvpack16";

// ---------------------------------------------------------------------------
// PeerFeatureFlags — bitflags matching Go's `peerFeatureFlag` iota
// ---------------------------------------------------------------------------

/// Bitfield of negotiated peer features.
///
/// Mirrors Go's `peerFeatureFlag` type (an `int` with `1 << iota` constants).
/// Each bit corresponds to a single feature capability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PeerFeatureFlags(u32);

impl PeerFeatureFlags {
    /// Proposal payload zstd compression.
    pub const COMPRESSED_PROPOSAL: Self = Self(1 << 0);

    /// Stateless agreement vote vpack compression.
    pub const COMPRESSED_VOTE_VPACK: Self = Self(1 << 1);

    /// Stateful agreement vote vpack compression — table size 2048.
    pub const COMPRESSED_VOTE_VPACK_STATEFUL_2048: Self = Self(1 << 2);

    /// Stateful agreement vote vpack compression — table size 1024.
    pub const COMPRESSED_VOTE_VPACK_STATEFUL_1024: Self = Self(1 << 3);

    /// Stateful agreement vote vpack compression — table size 512.
    pub const COMPRESSED_VOTE_VPACK_STATEFUL_512: Self = Self(1 << 4);

    /// Stateful agreement vote vpack compression — table size 256.
    pub const COMPRESSED_VOTE_VPACK_STATEFUL_256: Self = Self(1 << 5);

    /// Stateful agreement vote vpack compression — table size 128.
    pub const COMPRESSED_VOTE_VPACK_STATEFUL_128: Self = Self(1 << 6);

    /// Stateful agreement vote vpack compression — table size 64.
    pub const COMPRESSED_VOTE_VPACK_STATEFUL_64: Self = Self(1 << 7);

    /// Stateful agreement vote vpack compression — table size 32.
    pub const COMPRESSED_VOTE_VPACK_STATEFUL_32: Self = Self(1 << 8);

    /// Stateful agreement vote vpack compression — table size 16.
    pub const COMPRESSED_VOTE_VPACK_STATEFUL_16: Self = Self(1 << 9);

    /// Empty flag set — no features enabled.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns `true` if no feature bits are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if all bits in `other` are set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns the union of two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the intersection of two flag sets.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Returns `true` if any stateful vpack feature bit is set.
    pub const fn has_stateful_vpack(self) -> bool {
        let mask = Self::COMPRESSED_VOTE_VPACK_STATEFUL_2048.0
            | Self::COMPRESSED_VOTE_VPACK_STATEFUL_1024.0
            | Self::COMPRESSED_VOTE_VPACK_STATEFUL_512.0
            | Self::COMPRESSED_VOTE_VPACK_STATEFUL_256.0
            | Self::COMPRESSED_VOTE_VPACK_STATEFUL_128.0
            | Self::COMPRESSED_VOTE_VPACK_STATEFUL_64.0
            | Self::COMPRESSED_VOTE_VPACK_STATEFUL_32.0
            | Self::COMPRESSED_VOTE_VPACK_STATEFUL_16.0;
        self.0 & mask != 0
    }

    /// Returns the raw underlying bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// Given a (already-negotiated, i.e. intersected with our own advertised
/// bits) feature set, returns the stateful vpack table size both sides
/// agree on, or `0` if neither a matching stateful tier survived the
/// intersection.
///
/// # Deviation from go-algorand
///
/// Go's `wsPeer.getBestVpackTableSize()` (`network/wsPeer.go`) computes
/// `min(ourConfiguredSize, peerAdvertisedMaxSize)` from two independent
/// integers, so two peers configured with *different* nonzero table sizes
/// still converge on the smaller one. This function instead reads the
/// table size off a single already-intersected [`PeerFeatureFlags`] value
/// (see `connect.rs`'s `peer_features = remote_features.intersection(config.our_features)`),
/// so it only recovers a nonzero size when both sides advertised the
/// *same* tier bit. In the common case — every node using the matching
/// (typically default 2048) table size — this is exactly equivalent to
/// Go's min(); when two real nodes are configured with different nonzero
/// sizes, this conservatively disables stateful compression instead of
/// negotiating the smaller common size (falling back to the always-safe
/// stateless-only path, never to a wrong result).
pub const fn stateful_table_size(features: PeerFeatureFlags) -> u32 {
    if features.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_2048) {
        2048
    } else if features.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_1024) {
        1024
    } else if features.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_512) {
        512
    } else if features.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_256) {
        256
    } else if features.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_128) {
        128
    } else if features.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_64) {
        64
    } else if features.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_32) {
        32
    } else if features.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_16) {
        16
    } else {
        0
    }
}

/// Builds the [`PeerFeatureFlags`] this node should advertise during the
/// handshake, given whether stateless vote compression is enabled and
/// (if so) the normalized stateful table size (`0` disables the stateful
/// tier; must otherwise be one of `16, 32, 64, 128, 256, 512, 1024, 2048`
/// — matching go-algorand's `config.Local.NormalizedVoteCompressionTableSize`).
///
/// Always includes [`PeerFeatureFlags::COMPRESSED_PROPOSAL`], matching this
/// crate's existing default of always supporting zstd proposal compression.
///
/// Mirrors go-algorand's `network/wsNetwork.go` `setHeaders()`.
pub const fn advertise_vote_compression(enabled: bool, table_size: u32) -> PeerFeatureFlags {
    let mut flags = PeerFeatureFlags::COMPRESSED_PROPOSAL;
    if !enabled {
        return flags;
    }
    flags = flags.union(PeerFeatureFlags::COMPRESSED_VOTE_VPACK);
    let stateful = if table_size >= 2048 {
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_2048
    } else if table_size >= 1024 {
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_1024
    } else if table_size >= 512 {
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_512
    } else if table_size >= 256 {
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_256
    } else if table_size >= 128 {
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_128
    } else if table_size >= 64 {
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_64
    } else if table_size >= 32 {
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_32
    } else if table_size >= 16 {
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_16
    } else {
        PeerFeatureFlags::empty()
    };
    flags.union(stateful)
}

impl std::ops::BitOr for PeerFeatureFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for PeerFeatureFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for PeerFeatureFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for PeerFeatureFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

// ---------------------------------------------------------------------------
// Ordered list for deterministic encoding
// ---------------------------------------------------------------------------

/// All known features in canonical order (matching Go's iota order).
///
/// Used by [`encode_peer_features`] to produce a deterministic comma-separated
/// string.
const ALL_FEATURES: &[(PeerFeatureFlags, &str)] = &[
    (PeerFeatureFlags::COMPRESSED_PROPOSAL, FEATURE_STR_PPZSTD),
    (PeerFeatureFlags::COMPRESSED_VOTE_VPACK, FEATURE_STR_AVVPACK),
    (
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_2048,
        FEATURE_STR_AVVPACK2048,
    ),
    (
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_1024,
        FEATURE_STR_AVVPACK1024,
    ),
    (
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_512,
        FEATURE_STR_AVVPACK512,
    ),
    (
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_256,
        FEATURE_STR_AVVPACK256,
    ),
    (
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_128,
        FEATURE_STR_AVVPACK128,
    ),
    (
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_64,
        FEATURE_STR_AVVPACK64,
    ),
    (
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_32,
        FEATURE_STR_AVVPACK32,
    ),
    (
        PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_16,
        FEATURE_STR_AVVPACK16,
    ),
];

// ---------------------------------------------------------------------------
// Version gating helper
// ---------------------------------------------------------------------------

/// Parses a `"major.minor"` protocol version string into `(major, minor)`.
///
/// Returns `None` if the string does not have exactly two dot-separated integer
/// components.
fn parse_version(version: &str) -> Option<(i64, i64)> {
    let mut parts = version.split('.');
    let major_str = parts.next()?;
    let minor_str = parts.next()?;
    // Reject versions with more than two components (e.g. "1.2.3").
    if parts.next().is_some() {
        return None;
    }
    let major = major_str.parse::<i64>().ok()?;
    let minor = minor_str.parse::<i64>().ok()?;
    Some((major, minor))
}

/// Returns `true` if `version` is at least [`VERSION_PEER_FEATURES`] (`"2.2"`).
fn version_supports_features(version: &str) -> bool {
    let Some((major, minor)) = parse_version(version) else {
        return false;
    };
    // VERSION_PEER_FEATURES is "2.2"
    let (req_major, req_minor) = (2, 2);
    if major < req_major {
        return false;
    }
    if major == req_major && minor < req_minor {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Decodes a comma-separated feature string from the `X-Algorand-Peer-Features`
/// response header into a [`PeerFeatureFlags`] bitfield.
///
/// The `version` parameter is the negotiated network protocol version string
/// (e.g. `"2.2"`).  If the version is below `"2.2"`, all features are ignored
/// and an empty flag set is returned (matching Go's `decodePeerFeatures`).
///
/// Unknown feature names are silently ignored to preserve forward compatibility
/// — a newer peer may advertise features we don't yet recognise.
///
/// # Examples
///
/// ```
/// use algo_network::peer_features::{decode_peer_features, PeerFeatureFlags};
///
/// let flags = decode_peer_features("2.2", "ppzstd,avvpack");
/// assert!(flags.contains(PeerFeatureFlags::COMPRESSED_PROPOSAL));
/// assert!(flags.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK));
/// ```
pub fn decode_peer_features(version: &str, header_value: &str) -> PeerFeatureFlags {
    if !version_supports_features(version) {
        return PeerFeatureFlags::empty();
    }

    let mut flags = PeerFeatureFlags::empty();
    for token in header_value.split(',') {
        let name = token.trim();
        match name {
            FEATURE_STR_PPZSTD => flags |= PeerFeatureFlags::COMPRESSED_PROPOSAL,
            FEATURE_STR_AVVPACK => flags |= PeerFeatureFlags::COMPRESSED_VOTE_VPACK,
            FEATURE_STR_AVVPACK2048 => {
                flags |= PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_2048
            }
            FEATURE_STR_AVVPACK1024 => {
                flags |= PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_1024
            }
            FEATURE_STR_AVVPACK512 => flags |= PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_512,
            FEATURE_STR_AVVPACK256 => flags |= PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_256,
            FEATURE_STR_AVVPACK128 => flags |= PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_128,
            FEATURE_STR_AVVPACK64 => flags |= PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_64,
            FEATURE_STR_AVVPACK32 => flags |= PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_32,
            FEATURE_STR_AVVPACK16 => flags |= PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_16,
            "" => {} // empty token from leading/trailing commas or empty input
            unknown => {
                tracing::debug!(feature = unknown, "ignoring unknown peer feature");
            }
        }
    }
    flags
}

/// Encodes a [`PeerFeatureFlags`] bitfield into a comma-separated string
/// suitable for the `X-Algorand-Peer-Features` header.
///
/// Features appear in canonical order (matching Go's iota declaration order).
///
/// # Examples
///
/// ```
/// use algo_network::peer_features::{encode_peer_features, PeerFeatureFlags};
///
/// let flags = PeerFeatureFlags::COMPRESSED_PROPOSAL | PeerFeatureFlags::COMPRESSED_VOTE_VPACK;
/// assert_eq!(encode_peer_features(&flags), "ppzstd,avvpack");
/// ```
pub fn encode_peer_features(flags: &PeerFeatureFlags) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for &(flag, name) in ALL_FEATURES {
        if flags.contains(flag) {
            parts.push(name);
        }
    }
    parts.join(",")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- PeerFeatureFlags basic operations ------------------------------------

    #[test]
    fn empty_flags() {
        let f = PeerFeatureFlags::empty();
        assert!(f.is_empty());
        assert_eq!(f.bits(), 0);
    }

    #[test]
    fn single_flag_contains() {
        let f = PeerFeatureFlags::COMPRESSED_PROPOSAL;
        assert!(f.contains(PeerFeatureFlags::COMPRESSED_PROPOSAL));
        assert!(!f.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK));
    }

    #[test]
    fn union_and_intersection() {
        let a = PeerFeatureFlags::COMPRESSED_PROPOSAL;
        let b = PeerFeatureFlags::COMPRESSED_VOTE_VPACK;
        let u = a | b;
        assert!(u.contains(a));
        assert!(u.contains(b));
        assert_eq!(u.intersection(a), a);
    }

    #[test]
    fn has_stateful_vpack() {
        assert!(
            !PeerFeatureFlags::COMPRESSED_VOTE_VPACK.has_stateful_vpack(),
            "stateless vpack is not stateful"
        );
        assert!(PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_128.has_stateful_vpack());
        let combined = PeerFeatureFlags::COMPRESSED_PROPOSAL
            | PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_64;
        assert!(combined.has_stateful_vpack());
    }

    // -- Encode / decode roundtrip -------------------------------------------

    #[test]
    fn roundtrip_empty() {
        let flags = PeerFeatureFlags::empty();
        let encoded = encode_peer_features(&flags);
        assert_eq!(encoded, "");
        let decoded = decode_peer_features("2.2", &encoded);
        assert_eq!(decoded, flags);
    }

    #[test]
    fn roundtrip_single_ppzstd() {
        let flags = PeerFeatureFlags::COMPRESSED_PROPOSAL;
        let encoded = encode_peer_features(&flags);
        assert_eq!(encoded, "ppzstd");
        let decoded = decode_peer_features("2.2", &encoded);
        assert_eq!(decoded, flags);
    }

    #[test]
    fn roundtrip_single_avvpack() {
        let flags = PeerFeatureFlags::COMPRESSED_VOTE_VPACK;
        let encoded = encode_peer_features(&flags);
        assert_eq!(encoded, "avvpack");
        let decoded = decode_peer_features("2.2", &encoded);
        assert_eq!(decoded, flags);
    }

    #[test]
    fn roundtrip_ppzstd_and_avvpack() {
        let flags = PeerFeatureFlags::COMPRESSED_PROPOSAL | PeerFeatureFlags::COMPRESSED_VOTE_VPACK;
        let encoded = encode_peer_features(&flags);
        assert_eq!(encoded, "ppzstd,avvpack");
        let decoded = decode_peer_features("2.2", &encoded);
        assert_eq!(decoded, flags);
    }

    #[test]
    fn roundtrip_all_features() {
        let mut flags = PeerFeatureFlags::empty();
        for &(flag, _) in ALL_FEATURES {
            flags |= flag;
        }
        let encoded = encode_peer_features(&flags);
        let decoded = decode_peer_features("2.2", &encoded);
        assert_eq!(decoded, flags);
        // Verify the encoded string contains all feature names
        assert!(encoded.contains("ppzstd"));
        assert!(encoded.contains("avvpack16"));
        assert!(encoded.contains("avvpack2048"));
    }

    #[test]
    fn roundtrip_stateful_variants() {
        let flags = PeerFeatureFlags::COMPRESSED_VOTE_VPACK
            | PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_256;
        let encoded = encode_peer_features(&flags);
        assert_eq!(encoded, "avvpack,avvpack256");
        let decoded = decode_peer_features("2.2", &encoded);
        assert_eq!(decoded, flags);
    }

    // -- Decode: unknown features are ignored --------------------------------

    #[test]
    fn unknown_features_ignored() {
        let flags = decode_peer_features("2.2", "ppzstd,unknown_feature,avvpack");
        assert_eq!(
            flags,
            PeerFeatureFlags::COMPRESSED_PROPOSAL | PeerFeatureFlags::COMPRESSED_VOTE_VPACK
        );
    }

    #[test]
    fn all_unknown() {
        let flags = decode_peer_features("2.2", "foo,bar,baz");
        assert!(flags.is_empty());
    }

    // -- Decode: whitespace handling -----------------------------------------

    #[test]
    fn whitespace_trimmed() {
        let flags = decode_peer_features("2.2", " ppzstd , avvpack ");
        assert_eq!(
            flags,
            PeerFeatureFlags::COMPRESSED_PROPOSAL | PeerFeatureFlags::COMPRESSED_VOTE_VPACK
        );
    }

    // -- Decode: empty and edge cases ----------------------------------------

    #[test]
    fn empty_string_no_features() {
        let flags = decode_peer_features("2.2", "");
        assert!(flags.is_empty());
    }

    #[test]
    fn only_commas() {
        let flags = decode_peer_features("2.2", ",,,");
        assert!(flags.is_empty());
    }

    // -- Version gating (matching Go's TestDecodePeerFeatures) ---------------

    #[test]
    fn version_below_2_2_returns_empty() {
        // Versions below 2.2 should yield no features regardless of header.
        assert!(decode_peer_features("1.2", "ppzstd").is_empty());
        assert!(decode_peer_features("2.1", "ppzstd").is_empty());
        assert!(decode_peer_features("2.1", "").is_empty());
    }

    #[test]
    fn version_malformed_returns_empty() {
        assert!(decode_peer_features("1.2.3", "ppzstd").is_empty());
        assert!(decode_peer_features("a.b", "ppzstd").is_empty());
        assert!(decode_peer_features("", "ppzstd").is_empty());
    }

    #[test]
    fn version_2_2_works() {
        assert!(decode_peer_features("2.2", "").is_empty());
        assert!(decode_peer_features("2.2", "test").is_empty());
        assert!(decode_peer_features("2.2", "a,b").is_empty());
        assert_eq!(
            decode_peer_features("2.2", "ppzstd"),
            PeerFeatureFlags::COMPRESSED_PROPOSAL
        );
        assert_eq!(
            decode_peer_features("2.2", "ppzstd,test"),
            PeerFeatureFlags::COMPRESSED_PROPOSAL
        );
        assert_eq!(
            decode_peer_features("2.2", "ppzstd, test"),
            PeerFeatureFlags::COMPRESSED_PROPOSAL
        );
        assert_eq!(
            decode_peer_features("2.2", "ppzstd,avvpack"),
            PeerFeatureFlags::COMPRESSED_PROPOSAL | PeerFeatureFlags::COMPRESSED_VOTE_VPACK
        );
        assert_eq!(
            decode_peer_features("2.2", "avvpack"),
            PeerFeatureFlags::COMPRESSED_VOTE_VPACK
        );
    }

    #[test]
    fn version_above_2_2_works() {
        assert_eq!(
            decode_peer_features("2.3", "ppzstd"),
            PeerFeatureFlags::COMPRESSED_PROPOSAL
        );
        assert_eq!(
            decode_peer_features("3.0", "ppzstd"),
            PeerFeatureFlags::COMPRESSED_PROPOSAL
        );
    }

    // -- Encode ordering is deterministic ------------------------------------

    #[test]
    fn encode_ordering() {
        // Even if flags are OR'd in arbitrary order, encoding must be canonical.
        let flags = PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_16
            | PeerFeatureFlags::COMPRESSED_PROPOSAL
            | PeerFeatureFlags::COMPRESSED_VOTE_VPACK;
        let encoded = encode_peer_features(&flags);
        assert_eq!(encoded, "ppzstd,avvpack,avvpack16");
    }

    // -- parse_version helper ------------------------------------------------

    #[test]
    fn parse_version_valid() {
        assert_eq!(parse_version("2.2"), Some((2, 2)));
        assert_eq!(parse_version("1.0"), Some((1, 0)));
        assert_eq!(parse_version("10.99"), Some((10, 99)));
    }

    #[test]
    fn parse_version_invalid() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("2"), None);
        assert_eq!(parse_version("1.2.3"), None);
        assert_eq!(parse_version("a.b"), None);
    }

    // -- advertise_vote_compression / stateful_table_size --------------------

    #[test]
    fn advertise_vote_compression_disabled() {
        let flags = advertise_vote_compression(false, 2048);
        assert_eq!(flags, PeerFeatureFlags::COMPRESSED_PROPOSAL);
        assert_eq!(stateful_table_size(flags), 0);
    }

    #[test]
    fn advertise_vote_compression_stateless_only() {
        let flags = advertise_vote_compression(true, 0);
        assert!(flags.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK));
        assert!(!flags.has_stateful_vpack());
        assert_eq!(stateful_table_size(flags), 0);
    }

    #[test]
    fn advertise_vote_compression_stateful_default_2048() {
        let flags = advertise_vote_compression(true, 2048);
        assert!(flags.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK));
        assert!(flags.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_2048));
        assert_eq!(stateful_table_size(flags), 2048);
    }

    #[test]
    fn advertise_vote_compression_all_tiers() {
        let cases: &[(u32, u32)] = &[
            (16, 16),
            (32, 32),
            (64, 64),
            (128, 128),
            (256, 256),
            (512, 512),
            (1024, 1024),
            (2048, 2048),
            (4096, 2048), // above max clamps to 2048, matching go's `>= 2048` case
        ];
        for &(configured, expected) in cases {
            let flags = advertise_vote_compression(true, configured);
            assert_eq!(
                stateful_table_size(flags),
                expected,
                "configured={configured}"
            );
        }
    }

    #[test]
    fn stateful_table_size_no_stateful_bits() {
        assert_eq!(
            stateful_table_size(PeerFeatureFlags::COMPRESSED_VOTE_VPACK),
            0
        );
        assert_eq!(stateful_table_size(PeerFeatureFlags::empty()), 0);
    }

    #[test]
    fn stateful_table_size_highest_tier_wins() {
        // If somehow multiple tier bits are set, the highest one wins
        // (matches Go's switch-statement ordering from largest to smallest).
        let flags = PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_16
            | PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_256;
        assert_eq!(stateful_table_size(flags), 256);
    }

    // -- version_supports_features helper ------------------------------------

    #[test]
    fn version_gating() {
        assert!(!version_supports_features("1.0"));
        assert!(!version_supports_features("2.1"));
        assert!(version_supports_features("2.2"));
        assert!(version_supports_features("2.3"));
        assert!(version_supports_features("3.0"));
        assert!(!version_supports_features("a.b"));
        assert!(!version_supports_features("1.2.3"));
    }
}
