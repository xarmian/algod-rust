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
//! `to_rfc3339()` (auto fractional digits, `+00:00`).

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

/// `chrono::Utc::now().to_rfc3339()`.
pub fn now_rfc3339() -> String {
    rfc3339_auto(OffsetDateTime::now_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_auto_matches_chrono() {
        let at = |n| OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap().replace_nanosecond(n).unwrap();
        assert_eq!(rfc3339_auto(at(0)), "2023-11-14T22:13:20+00:00");
        assert_eq!(rfc3339_auto(at(120_000_000)), "2023-11-14T22:13:20.120+00:00");
        assert_eq!(rfc3339_auto(at(123_456_000)), "2023-11-14T22:13:20.123456+00:00");
        assert_eq!(rfc3339_auto(at(123_456_789)), "2023-11-14T22:13:20.123456789+00:00");
        assert!(now_rfc3339().ends_with("+00:00"));
    }
}
