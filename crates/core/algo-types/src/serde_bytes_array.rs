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

//! Zero-allocation serde helpers for fixed-size byte arrays.
//!
//! These modules serialize fixed-size byte arrays as msgpack `bin` (same as
//! `serde_bytes::ByteBuf`) but deserialize directly into stack-allocated arrays
//! via a custom Visitor, avoiding the intermediate `Vec<u8>` heap allocation.

use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};
use std::fmt;

// ── Visitor implementations ──────────────────────────────────────

struct ByteArray32Visitor;

impl<'de> Visitor<'de> for ByteArray32Visitor {
    type Value = [u8; 32];

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("32 bytes")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<[u8; 32], E> {
        v.try_into()
            .map_err(|_| E::custom(format!("expected 32 bytes, got {}", v.len())))
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<[u8; 32], E> {
        v.as_slice()
            .try_into()
            .map_err(|_| E::custom(format!("expected 32 bytes, got {}", v.len())))
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 32], A::Error> {
        let mut arr = [0u8; 32];
        for (i, byte) in arr.iter_mut().enumerate() {
            *byte = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(i, &self))?;
        }
        Ok(arr)
    }
}

struct ByteArray64Visitor;

impl<'de> Visitor<'de> for ByteArray64Visitor {
    type Value = [u8; 64];

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("64 bytes")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<[u8; 64], E> {
        v.try_into()
            .map_err(|_| E::custom(format!("expected 64 bytes, got {}", v.len())))
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<[u8; 64], E> {
        v.as_slice()
            .try_into()
            .map_err(|_| E::custom(format!("expected 64 bytes, got {}", v.len())))
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 64], A::Error> {
        let mut arr = [0u8; 64];
        for (i, byte) in arr.iter_mut().enumerate() {
            *byte = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(i, &self))?;
        }
        Ok(arr)
    }
}

// ── Helper predicates (for skip_serializing_if) ──────────────────

/// Returns `true` when all 32 bytes are zero (the "empty" / omit-on-encode value).
pub fn is_zero_32(v: &[u8; 32]) -> bool {
    *v == [0u8; 32]
}

/// Returns `true` when all 64 bytes are zero.
pub fn is_zero_64(v: &[u8; 64]) -> bool {
    *v == [0u8; 64]
}

/// Returns `true` when the option is `None` or all bytes are zero.
pub fn is_none_or_zero_32(v: &Option<[u8; 32]>) -> bool {
    match v {
        None => true,
        Some(arr) => *arr == [0u8; 32],
    }
}

/// Returns `true` when the option is `None` or all bytes are zero.
pub fn is_none_or_zero_64(v: &Option<[u8; 64]>) -> bool {
    match v {
        None => true,
        Some(arr) => *arr == [0u8; 64],
    }
}

/// Default value helper for `[u8; 64]` fields (stable Rust lacks `Default` for arrays > 32).
pub fn zeros_64() -> [u8; 64] {
    [0u8; 64]
}

// ── serde_bytes_32: required [u8; 32] ────────────────────────────

/// Serde module for a required `[u8; 32]` field encoded as msgpack `bin`.
pub mod serde_bytes_32 {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v.as_slice())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        d.deserialize_bytes(ByteArray32Visitor)
    }
}

// ── serde_bytes_64: required [u8; 64] ────────────────────────────

/// Serde module for a required `[u8; 64]` field encoded as msgpack `bin`.
pub mod serde_bytes_64 {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v.as_slice())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        d.deserialize_bytes(ByteArray64Visitor)
    }
}

// ── serde_bytes_32_opt: Option<[u8; 32]> ─────────────────────────

/// Serde module for an optional `[u8; 32]` field encoded as msgpack `bin`.
pub mod serde_bytes_32_opt {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(arr) => s.serialize_bytes(arr.as_slice()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        struct OptVisitor;

        impl<'de> Visitor<'de> for OptVisitor {
            type Value = Option<[u8; 32]>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("null or 32 bytes")
            }

            fn visit_none<E: de::Error>(self) -> Result<Option<[u8; 32]>, E> {
                Ok(None)
            }

            fn visit_unit<E: de::Error>(self) -> Result<Option<[u8; 32]>, E> {
                Ok(None)
            }

            fn visit_some<D2: Deserializer<'de>>(
                self,
                d: D2,
            ) -> Result<Option<[u8; 32]>, D2::Error> {
                d.deserialize_bytes(ByteArray32Visitor).map(Some)
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Option<[u8; 32]>, E> {
                ByteArray32Visitor.visit_bytes(v).map(Some)
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Option<[u8; 32]>, E> {
                ByteArray32Visitor.visit_byte_buf(v).map(Some)
            }
        }

        d.deserialize_option(OptVisitor)
    }
}

// ── serde_bytes_64_opt: Option<[u8; 64]> ─────────────────────────

/// Serde module for an optional `[u8; 64]` field encoded as msgpack `bin`.
pub mod serde_bytes_64_opt {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<[u8; 64]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(arr) => s.serialize_bytes(arr.as_slice()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 64]>, D::Error> {
        struct OptVisitor;

        impl<'de> Visitor<'de> for OptVisitor {
            type Value = Option<[u8; 64]>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("null or 64 bytes")
            }

            fn visit_none<E: de::Error>(self) -> Result<Option<[u8; 64]>, E> {
                Ok(None)
            }

            fn visit_unit<E: de::Error>(self) -> Result<Option<[u8; 64]>, E> {
                Ok(None)
            }

            fn visit_some<D2: Deserializer<'de>>(
                self,
                d: D2,
            ) -> Result<Option<[u8; 64]>, D2::Error> {
                d.deserialize_bytes(ByteArray64Visitor).map(Some)
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Option<[u8; 64]>, E> {
                ByteArray64Visitor.visit_bytes(v).map(Some)
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Option<[u8; 64]>, E> {
                ByteArray64Visitor.visit_byte_buf(v).map(Some)
            }
        }

        d.deserialize_option(OptVisitor)
    }
}
