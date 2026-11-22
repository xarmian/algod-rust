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

//! The two checks go's `crypto/x509` `Certificate.Verify` runs on the leaf
//! before it builds a chain (issue #2507), with go's error texts: the
//! validity period (`isValid`: `x509: certificate has expired or is not yet
//! valid: current time T is after|before T`) and the host name
//! (`VerifyHostname`: `HostnameError`). They come first in go, so an
//! untrusted certificate that is also expired, or for another name, is
//! reported as that and not as `signed by unknown authority`.

use std::net::IpAddr;

/// The parts of a leaf certificate those checks read.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Leaf {
    /// `NotBefore`, Unix seconds.
    pub not_before: i64,
    /// `NotAfter`, Unix seconds.
    pub not_after: i64,
    /// The `dNSName` subject alternative names.
    pub dns: Vec<String>,
    /// The `iPAddress` subject alternative names.
    pub ips: Vec<IpAddr>,
}

/// One DER element: its tag, its content and what follows it.
pub(crate) fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)?;
    let (len, hdr) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*b.get(2 + i)?);
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    Some((tag, b.get(hdr..end)?, b.get(end..)?))
}

/// The parsed leaf, or `None` when the DER is not a certificate this reads.
pub fn parse_leaf(der: &[u8]) -> Option<Leaf> {
    let (_, cert, _) = tlv(der)?;
    let (_, tbs, _) = tlv(cert)?;
    let mut rest = tbs;
    // the optional [0] version
    let (tag, _, after) = tlv(rest)?;
    if tag == 0xa0 {
        rest = after;
    }
    // serial, signature, issuer
    for _ in 0..3 {
        rest = tlv(rest)?.2;
    }
    let (_, validity, rest) = tlv(rest)?;
    let (t1, nb, v) = tlv(validity)?;
    let (t2, na, _) = tlv(v)?;
    let mut leaf = Leaf {
        not_before: parse_time(t1, nb)?,
        not_after: parse_time(t2, na)?,
        ..Leaf::default()
    };
    // subject, subjectPublicKeyInfo, then the optional [1], [2] and [3]
    let mut rest = tlv(tlv(rest)?.2)?.2;
    while !rest.is_empty() {
        let (tag, body, after) = tlv(rest)?;
        rest = after;
        if tag != 0xa3 {
            continue;
        }
        let (_, exts, _) = tlv(body)?;
        let mut exts = exts;
        while !exts.is_empty() {
            let (_, ext, after) = tlv(exts)?;
            exts = after;
            let (_, oid, e) = tlv(ext)?;
            // subjectAltName 2.5.29.17
            if oid != [0x55, 0x1d, 0x11] {
                continue;
            }
            let (mut t, mut value, _) = tlv(e)?;
            if t == 0x01 {
                // the optional `critical` flag
                (t, value, _) = tlv(tlv(e)?.2)?;
            }
            if t != 0x04 {
                return None;
            }
            let (_, names, _) = tlv(value)?;
            let mut names = names;
            while !names.is_empty() {
                let (tag, name, after) = tlv(names)?;
                names = after;
                match (tag, name.len()) {
                    (0x82, _) => leaf.dns.push(String::from_utf8_lossy(name).into_owned()),
                    (0x87, 4) => {
                        leaf.ips.push(IpAddr::from(<[u8; 4]>::try_from(name).ok()?));
                    }
                    (0x87, 16) => {
                        leaf.ips
                            .push(IpAddr::from(<[u8; 16]>::try_from(name).ok()?));
                    }
                    _ => {}
                }
            }
        }
    }
    Some(leaf)
}

/// A `UTCTime` (`YYMMDDHHMMSSZ`) or `GeneralizedTime` (`YYYYMMDDHHMMSSZ`).
pub(crate) fn parse_time(tag: u8, b: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(b).ok()?;
    let s = s.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if s.len() == 12 => {
            let yy: i64 = s[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
        }
        0x18 if s.len() == 14 => (s[..4].parse().ok()?, &s[4..]),
        _ => return None,
    };
    let n = |i: usize| rest.get(i..i + 2)?.parse::<i64>().ok();
    let (mon, day, h, m, sec) = (n(0)?, n(2)?, n(4)?, n(6)?, n(8)?);
    Some(days_from_civil(year, mon, day) * 86400 + h * 3600 + m * 60 + sec)
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// The date of a day count (the inverse of [`days_from_civil`]).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// go's `time.Format(time.RFC3339)` of `unix` in a zone `offset` seconds east
/// of UTC (`Z` at 0).
pub fn rfc3339(unix: i64, offset: i32) -> String {
    let t = unix + i64::from(offset);
    let (y, mo, d) = civil_from_days(t.div_euclid(86400));
    let s = t.rem_euclid(86400);
    let zone = if offset == 0 {
        "Z".to_string()
    } else {
        let sign = if offset < 0 { '-' } else { '+' };
        let a = offset.unsigned_abs();
        format!("{sign}{:02}:{:02}", a / 3600, a % 3600 / 60)
    };
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}{zone}",
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

/// The local zone's offset east of UTC at `unix` (go prints the current time
/// in its local zone).
pub fn local_offset(unix: i64) -> i32 {
    let t = unix as libc::time_t;
    // SAFETY: `tm` is plain data that `localtime_r` fills; `t` is a valid
    // time_t.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff as i32
    }
}

/// go's `isValid` period check at `now` (Unix seconds): the text of its
/// error, without the `tls: failed to verify certificate: ` prefix.
pub fn validity_error(leaf: &Leaf, now: i64) -> Option<String> {
    let off = local_offset(now);
    let (what, other) = if now < leaf.not_before {
        ("before", leaf.not_before)
    } else if now > leaf.not_after {
        ("after", leaf.not_after)
    } else {
        return None;
    };
    Some(format!(
        "x509: certificate has expired or is not yet valid: current time {} is {what} {}",
        rfc3339(now, off),
        rfc3339(other, 0)
    ))
}

/// go's `matchHostnames`: `*` as a whole leftmost label matches one label.
fn match_hostnames(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    let host = host.trim_end_matches('.');
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    let p: Vec<&str> = pattern.split('.').collect();
    let h: Vec<&str> = host.split('.').collect();
    if p.len() != h.len() {
        return false;
    }
    p.iter()
        .zip(&h)
        .enumerate()
        .all(|(i, (pl, hl))| (i == 0 && *pl == "*") || pl == hl)
}

/// go's `VerifyHostname` of `host` (a name or an IP literal, no port): the
/// text of its `HostnameError`, or `None` when the leaf is valid for it.
pub fn name_error(leaf: &Leaf, host: &str) -> Option<String> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        if leaf.ips.contains(&ip) {
            return None;
        }
        if leaf.ips.is_empty() {
            return Some(format!(
                "x509: cannot validate certificate for {host} because it doesn't contain any IP SANs"
            ));
        }
        let valid: Vec<String> = leaf.ips.iter().map(IpAddr::to_string).collect();
        return Some(format!(
            "x509: certificate is valid for {}, not {host}",
            valid.join(", ")
        ));
    }
    let lower = host.to_ascii_lowercase();
    if leaf.dns.iter().any(|d| {
        lower == d.to_ascii_lowercase() || match_hostnames(&d.to_ascii_lowercase(), &lower)
    }) {
        return None;
    }
    if leaf.dns.is_empty() {
        return Some(format!(
            "x509: certificate is not valid for any names, but wanted to match {host}"
        ));
    }
    Some(format!(
        "x509: certificate is valid for {}, not {host}",
        leaf.dns.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_round_trip() {
        for t in [0i64, 1577836800, 4070908800, 1795301392, -86400] {
            let days = t.div_euclid(86400);
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(rfc3339(1577836800, 0), "2020-01-01T00:00:00Z");
        assert_eq!(rfc3339(4070908800, 0), "2099-01-01T00:00:00Z");
        assert_eq!(rfc3339(1577836800, 3600), "2020-01-01T01:00:00+01:00");
        assert_eq!(
            rfc3339(1577836800, -5 * 3600 - 1800),
            "2019-12-31T18:30:00-05:30"
        );
    }

    #[test]
    fn wildcard_names_like_go() {
        assert!(match_hostnames("*.example.com", "a.example.com"));
        assert!(!match_hostnames("*.example.com", "a.b.example.com"));
        assert!(!match_hostnames("*.example.com", "example.com"));
        assert!(match_hostnames("example.com.", "example.com"));
        assert!(!match_hostnames("a*.example.com", "ab.example.com"));
    }

    #[test]
    fn names_error_like_go() {
        let leaf = Leaf {
            dns: vec!["example.com".into(), "www.example.com".into()],
            ips: vec!["127.0.0.2".parse().unwrap()],
            ..Leaf::default()
        };
        assert_eq!(name_error(&leaf, "EXAMPLE.com"), None);
        assert_eq!(name_error(&leaf, "127.0.0.2"), None);
        assert_eq!(
            name_error(&leaf, "127.0.0.1").unwrap(),
            "x509: certificate is valid for 127.0.0.2, not 127.0.0.1"
        );
        assert_eq!(
            name_error(&leaf, "algod.test").unwrap(),
            "x509: certificate is valid for example.com, www.example.com, not algod.test"
        );
        assert_eq!(
            name_error(&Leaf::default(), "127.0.0.1").unwrap(),
            "x509: cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs"
        );
        assert_eq!(
            name_error(&Leaf::default(), "algod.test").unwrap(),
            "x509: certificate is not valid for any names, but wanted to match algod.test"
        );
    }
}
