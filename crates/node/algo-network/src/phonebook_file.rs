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

//! `phonebook.json` include-list loader (issue #949).
//!
//! Mirrors go-algorand's `config.LoadPhonebook`/`config.SavePhonebookToDisk`
//! (`config/config.go:193-236`). Go's own comment on the feature says it
//! best: "We no longer use phonebook for anything but tests, but users
//! should be able to use it" — this is a legacy, optional operator
//! escape hatch for pinning a bootstrap peer allow-list independent of DNS
//! discovery, not a primary peer-discovery mechanism.
//!
//! The on-disk format is a single JSON object with one field:
//! `{"Include": ["relay1.example.com:4160", "relay2.example.com:4160"]}` —
//! go's `phonebookBlackWhiteList` struct, despite its name, only ever reads
//! (or writes) `Include`; there is no separate exclude list upstream.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Filename go-algorand (and algod-rust) reads relative to the node's data
/// directory. Go: `config.PhonebookFilename` (`config/config.go:64`).
pub const PHONEBOOK_FILENAME: &str = "phonebook.json";

/// Errors from loading `phonebook.json`.
#[derive(Debug, thiserror::Error)]
pub enum PhonebookFileError {
    /// The file exists but could not be read (permissions, I/O failure,
    /// etc.) — NOT raised for a merely-absent file, which is treated as "no
    /// include list configured" (matching go's `os.IsNotExist` check).
    #[error("failed to read {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The file's JSON could not be parsed. Go:
    /// `"error decoding phonebook! got error: " + err.Error()`.
    #[error("error decoding phonebook! got error: {0}")]
    Parse(#[source] serde_json::Error),
}

/// Loads the `Include` address list from `<data_dir>/phonebook.json`, if the
/// file exists. Mirrors go's `config.LoadPhonebook`: a missing file is not
/// an error and yields an empty list; any other I/O failure or malformed
/// JSON is.
pub fn load_phonebook(data_dir: &Path) -> Result<Vec<String>, PhonebookFileError> {
    let path = data_dir.join(PHONEBOOK_FILENAME);
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(PhonebookFileError::Io { path, source: e }),
    };
    let parsed: RawPhonebook =
        serde_json::from_str(&contents).map_err(PhonebookFileError::Parse)?;
    Ok(parsed.include)
}

/// Writes `entries` to `<root>/phonebook.json`, overwriting any existing
/// file. Mirrors go's `config.SavePhonebookToDisk`.
pub fn save_phonebook(entries: &[String], root: &Path) -> Result<(), PhonebookFileError> {
    let path = root.join(PHONEBOOK_FILENAME);
    let raw = RawPhonebook {
        include: entries.to_vec(),
    };
    let json = serde_json::to_string_pretty(&raw).map_err(PhonebookFileError::Parse)?;
    fs::write(&path, json).map_err(|e| PhonebookFileError::Io { path, source: e })
}

/// On-disk shape of `phonebook.json`. Go: `phonebookBlackWhiteList`
/// (`config/config.go:189`) — despite the name, it only ever has an
/// `Include` field (no separate exclude list upstream); that field name is
/// the literal JSON key (go's struct carries no `json:"..."` tag, so
/// encoding/json uses the field name verbatim).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RawPhonebook {
    #[serde(rename = "Include", default)]
    include: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "algo-network-phonebook-file-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_file_returns_empty_list_not_error() {
        let dir = temp_dir("missing");
        let result = load_phonebook(&dir).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn round_trips_a_real_include_list() {
        let dir = temp_dir("roundtrip");
        let entries = vec![
            "relay1.example.com:4160".to_string(),
            "relay2.example.com:4160".to_string(),
        ];
        save_phonebook(&entries, &dir).unwrap();
        let loaded = load_phonebook(&dir).unwrap();
        assert_eq!(loaded, entries);
    }

    #[test]
    fn loads_a_hand_written_go_style_file() {
        let dir = temp_dir("go-style");
        fs::write(
            dir.join(PHONEBOOK_FILENAME),
            r#"{"Include": ["10.0.0.1:4160", "10.0.0.2:4160"]}"#,
        )
        .unwrap();
        let loaded = load_phonebook(&dir).unwrap();
        assert_eq!(
            loaded,
            vec!["10.0.0.1:4160".to_string(), "10.0.0.2:4160".to_string()]
        );
    }

    #[test]
    fn empty_include_list_round_trips() {
        let dir = temp_dir("empty");
        save_phonebook(&[], &dir).unwrap();
        let loaded = load_phonebook(&dir).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn malformed_json_is_a_parse_error_not_a_panic() {
        let dir = temp_dir("malformed");
        fs::write(dir.join(PHONEBOOK_FILENAME), "not json").unwrap();
        let err = load_phonebook(&dir).unwrap_err();
        assert!(matches!(err, PhonebookFileError::Parse(_)));
    }
}
