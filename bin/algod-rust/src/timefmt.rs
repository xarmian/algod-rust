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

//! UTC timestamp formatting helpers (issue #2402).
//!
//! Replaces `chrono` (RUSTSEC-2026-0543, unmaintained) with `time` while
//! keeping every emitted string byte-identical to chrono's output:
//! `to_rfc3339()` (auto fractional digits, `+00:00`),
//! `to_rfc3339_opts(Millis, true)` (3 digits, `Z`) and
//! `format("%Y%m%dT%H%M%S%.3fZ")`.

use time::OffsetDateTime;

fn base(dt: &OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

/// Same as `chrono::DateTime<Utc>::to_rfc3339()`.
pub fn rfc3339_auto(dt: OffsetDateTime) -> String {
    let dt = dt.to_offset(time::UtcOffset::UTC);
    let n = dt.nanosecond();
    let frac = if n == 0 {
        String::new()
    } else if n.is_multiple_of(1_000_000) {
        format!(".{:03}", n / 1_000_000)
    } else if n.is_multiple_of(1_000) {
        format!(".{:06}", n / 1_000)
    } else {
        format!(".{n:09}")
    };
    format!("{}{frac}+00:00", base(&dt))
}

/// Same as `to_rfc3339_opts(SecondsFormat::Millis, true)`.
pub fn rfc3339_millis_z(dt: OffsetDateTime) -> String {
    let dt = dt.to_offset(time::UtcOffset::UTC);
    format!("{}.{:03}Z", base(&dt), dt.nanosecond() / 1_000_000)
}

/// Same as `format("%Y%m%dT%H%M%S%.3fZ")`.
pub fn compact_millis_z(dt: OffsetDateTime) -> String {
    let dt = dt.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}.{:03}Z",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.nanosecond() / 1_000_000
    )
}

/// `chrono::Utc::now().to_rfc3339()`.
pub fn now_rfc3339() -> String {
    rfc3339_auto(OffsetDateTime::now_utc())
}

/// `chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()`.
pub fn now_unix_nanos() -> i64 {
    i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64, nanos: u32) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).unwrap().replace_nanosecond(nanos).unwrap()
    }

    // 1_700_000_000 = 2023-11-14T22:13:20Z. Expected strings were produced
    // by chrono 0.4 before the swap.
    #[test]
    fn rfc3339_auto_matches_chrono() {
        assert_eq!(rfc3339_auto(at(1_700_000_000, 0)), "2023-11-14T22:13:20+00:00");
        assert_eq!(rfc3339_auto(at(1_700_000_000, 120_000_000)), "2023-11-14T22:13:20.120+00:00");
        assert_eq!(rfc3339_auto(at(1_700_000_000, 123_456_000)), "2023-11-14T22:13:20.123456+00:00");
        assert_eq!(rfc3339_auto(at(1_700_000_000, 123_456_789)), "2023-11-14T22:13:20.123456789+00:00");
        assert_eq!(rfc3339_auto(at(0, 5)), "1970-01-01T00:00:00.000000005+00:00");
    }

    #[test]
    fn millis_z_matches_chrono() {
        assert_eq!(rfc3339_millis_z(at(1_700_000_000, 0)), "2023-11-14T22:13:20.000Z");
        assert_eq!(rfc3339_millis_z(at(1_700_000_000, 123_999_999)), "2023-11-14T22:13:20.123Z");
        assert_eq!(compact_millis_z(at(1_700_000_000, 123_999_999)), "20231114T221320.123Z");
    }

    #[test]
    fn now_helpers_are_sane() {
        assert!(now_rfc3339().ends_with("+00:00"));
        assert!(now_unix_nanos() > 1_700_000_000_000_000_000);
    }
}
