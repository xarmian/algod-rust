//! API-token authentication primitives.
//!
//! Ported from `../go-algorand/util/tokens/tokens.go` (v4.5.1-stable):
//! `ValidateOrGenerateAPIToken`, `ValidateAPIToken`,
//! `GetAndValidateAPIToken`, plus the `KmdTokenFilename` constant.
//!
//! The token is a hex string of `≥ 64 && ≤ 256` characters stored at
//! `<data_dir>/kmd.token`. On first daemon start we generate one if
//! the file is missing; subsequent starts read it back.

use std::path::{Path, PathBuf};

use rand::RngCore;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

/// Filename of the kmd API token. Matches `KmdTokenFilename`
/// (`util/tokens/tokens.go:35`).
pub const KMD_TOKEN_FILENAME: &str = "kmd.token";

/// `minimumAPITokenLength` (tokens.go:28). Tokens shorter than 64 hex
/// characters are rejected.
pub const MINIMUM_API_TOKEN_LENGTH: usize = 64;

/// `maximumAPITokenLength` (tokens.go:29).
pub const MAXIMUM_API_TOKEN_LENGTH: usize = 256;

/// Hex-encoded entropy length used by `GenerateAPIToken` —
/// `(minimumAPITokenLength + 1) / 2` raw bytes → exactly 64 hex chars.
/// Go writes this as `(minimumAPITokenLength + 1) / 2`; clippy prefers
/// the `div_ceil` form in Rust.
const ENTROPY_LEN: usize = MINIMUM_API_TOKEN_LENGTH.div_ceil(2);

/// Validate an API-token string per Go's rules (`ValidateAPIToken`,
/// tokens.go:92): length only — content is not parsed.
pub fn validate_api_token(token: &str) -> Result<()> {
    if token.len() < MINIMUM_API_TOKEN_LENGTH {
        return Err(Error::ApiTokenTooShort);
    }
    if token.len() > MAXIMUM_API_TOKEN_LENGTH {
        return Err(Error::ApiTokenTooLong);
    }
    Ok(())
}

/// Constant-time equality check. Use this for every bearer-token
/// comparison so a timing oracle can't reveal a partial match.
pub fn token_eq(presented: &str, expected: &str) -> bool {
    presented.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Read `<data_dir>/kmd.token` and validate the first line. Mirrors
/// `GetAndValidateAPIToken` (tokens.go:44). Returns the token string
/// on success, or an error if the file is missing / malformed.
pub fn get_and_validate_api_token(data_dir: &Path) -> Result<String> {
    let path = token_path(data_dir);
    let raw = std::fs::read_to_string(&path).map_err(Error::Io)?;
    let first_line = raw.lines().next().unwrap_or("").to_string();
    validate_api_token(&first_line)?;
    Ok(first_line)
}

/// Generate a fresh API token, persist it to disk, and return it.
/// Mirrors `GenerateAPIToken` (tokens.go:66). Uses the OS RNG +
/// hex encoding to produce a 64-char token.
pub fn generate_api_token(data_dir: &Path) -> Result<String> {
    let mut entropy = vec![0u8; ENTROPY_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut entropy)
        .map_err(|_| Error::RandBytes)?;
    let hex_token = hex_lowercase(&entropy);
    validate_api_token(&hex_token)?;
    let path = token_path(data_dir);
    std::fs::write(&path, hex_token.as_bytes()).map_err(Error::Io)?;
    Ok(hex_token)
}

/// Read the existing token, or generate one if missing. Mirrors
/// `ValidateOrGenerateAPIToken` (tokens.go:106). Idempotent: calling
/// twice with the same data dir returns the same token.
///
/// **Important parity note**: a present-but-invalid token is
/// **preserved**, not regenerated — the function surfaces the
/// validation error instead of silently rotating a corrupted/
/// misconfigured token. Go's logic at tokens.go:108–122:
///
/// ```text
/// apiToken, _ := GetAndValidateAPIToken(...)   // ignore read err
/// if apiToken == "" { apiToken, err = GenerateAPIToken(...) }
/// err = ValidateAPIToken(apiToken)             // surface validation
/// return
/// ```
///
/// We only generate when the file is genuinely missing or empty;
/// any present content goes through `validate_api_token` and the
/// caller sees the underlying length error rather than getting a
/// silently-rewritten token that invalidates every existing client.
pub fn validate_or_generate_api_token(data_dir: &Path) -> Result<String> {
    // Read the first line. `NotFound` becomes `Ok("")` (the
    // "generate" trigger); other read failures (permission denied,
    // invalid UTF-8, …) propagate up so a misconfigured daemon
    // doesn't silently rotate its API token and invalidate every
    // existing client.
    //
    // This is a deliberate divergence from Go's
    // `apiToken, _ := GetAndValidateAPIToken(...)` (tokens.go:108)
    // which ignores all read errors and treats any failure mode as
    // "generate". Our behavior is a strict superset: anything Go
    // accepts (file missing → generate; file present + valid → use;
    // file present + invalid → surface ApiToken{TooShort,TooLong}),
    // we also accept identically. We additionally surface
    // PermissionDenied / IO errors that Go silently swallowed.
    let read_token = read_first_line(data_dir)?;

    let token = if read_token.is_empty() {
        generate_api_token(data_dir)?
    } else {
        read_token
    };

    validate_api_token(&token)?;
    Ok(token)
}

/// Helper used by [`validate_or_generate_api_token`]: read the token
/// file's first line, returning `Ok("")` only when the file is
/// genuinely absent so the caller can hit the "generate" branch.
/// Other I/O errors are surfaced.
fn read_first_line(data_dir: &Path) -> Result<String> {
    let path = token_path(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(raw) => Ok(raw.lines().next().unwrap_or("").to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(Error::Io(e)),
    }
}

fn token_path(data_dir: &Path) -> PathBuf {
    data_dir.join(KMD_TOKEN_FILENAME)
}

/// Lowercase hex encoding, matching Go's `fmt.Sprintf("%x", b)`.
fn hex_lowercase(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn validate_rejects_short_and_long() {
        assert!(matches!(
            validate_api_token(""),
            Err(Error::ApiTokenTooShort)
        ));
        let short = "a".repeat(MINIMUM_API_TOKEN_LENGTH - 1);
        assert!(matches!(
            validate_api_token(&short),
            Err(Error::ApiTokenTooShort)
        ));
        let ok = "a".repeat(MINIMUM_API_TOKEN_LENGTH);
        assert!(validate_api_token(&ok).is_ok());
        let too_long = "a".repeat(MAXIMUM_API_TOKEN_LENGTH + 1);
        assert!(matches!(
            validate_api_token(&too_long),
            Err(Error::ApiTokenTooLong)
        ));
    }

    #[test]
    fn token_eq_matches_only_identical_bytes() {
        let a = "a".repeat(64);
        let b = "a".repeat(64);
        assert!(token_eq(&a, &b));
        let c = format!("{}b", &a[..63]);
        assert!(!token_eq(&a, &c));
        // Different lengths never match.
        let d = "a".repeat(65);
        assert!(!token_eq(&a, &d));
    }

    #[test]
    fn validate_or_generate_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let t1 = validate_or_generate_api_token(dir.path()).unwrap();
        let t2 = validate_or_generate_api_token(dir.path()).unwrap();
        assert_eq!(t1, t2, "second call must return the persisted token");
        // The on-disk token must validate and equal what we got back.
        let on_disk = std::fs::read_to_string(dir.path().join(KMD_TOKEN_FILENAME)).unwrap();
        assert_eq!(on_disk, t1);
        assert_eq!(t1.len(), MINIMUM_API_TOKEN_LENGTH);
        // All hex characters.
        assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn get_and_validate_reads_first_line_only() {
        let dir = TempDir::new().unwrap();
        let tok = "a".repeat(64);
        std::fs::write(
            dir.path().join(KMD_TOKEN_FILENAME),
            format!("{tok}\nignored second line"),
        )
        .unwrap();
        let got = get_and_validate_api_token(dir.path()).unwrap();
        assert_eq!(got, tok);
    }

    #[test]
    fn existing_invalid_token_is_preserved_not_rotated() {
        // Regression for Codex PR #354 round 1: Go preserves a
        // present-but-invalid kmd.token (surfaces ApiTokenTooShort)
        // rather than silently regenerating it. Rotating a token
        // unexpectedly invalidates every existing client and hides
        // startup config bugs.
        let dir = TempDir::new().unwrap();
        let short_token = "abc"; // 3 chars — well under the 64 min
        std::fs::write(dir.path().join(KMD_TOKEN_FILENAME), short_token).unwrap();

        // First call must surface the validation error.
        let err = validate_or_generate_api_token(dir.path()).unwrap_err();
        assert!(
            matches!(err, Error::ApiTokenTooShort),
            "expected ApiTokenTooShort, got {err:?}"
        );

        // The on-disk file must remain unchanged — no silent rotation.
        let after = std::fs::read_to_string(dir.path().join(KMD_TOKEN_FILENAME)).unwrap();
        assert_eq!(
            after, short_token,
            "validate_or_generate must not rewrite a present-but-invalid token"
        );
    }

    #[test]
    fn empty_token_file_triggers_generation() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(KMD_TOKEN_FILENAME), "").unwrap();
        let token = validate_or_generate_api_token(dir.path()).unwrap();
        assert_eq!(token.len(), MINIMUM_API_TOKEN_LENGTH);
        // Subsequent call returns the same (now-persisted) token.
        let again = validate_or_generate_api_token(dir.path()).unwrap();
        assert_eq!(token, again);
    }

    #[test]
    fn hex_lowercase_matches_go_format() {
        // Spot-check a few values vs the expected `fmt.Sprintf("%x")`
        // output Go would produce.
        assert_eq!(hex_lowercase(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_lowercase(&[0xab, 0xcd, 0xef]), "abcdef");
        assert_eq!(hex_lowercase(&[]), "");
    }
}
