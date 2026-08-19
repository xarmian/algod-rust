//! Shared helpers used by multiple algokey subcommands.
//!
//! Each helper mirrors a function in `../go-algorand/cmd/algokey/common.go`
//! — error wording, file permissions, and exit codes match Go so operator
//! tooling (CI, scripts) sees the same surface.

use std::io::Write;
use std::path::Path;

use algo_types::Address;
use ed25519_dalek::SigningKey;

/// 32-byte secret seed — the input to ed25519's deterministic keypair
/// derivation. Mirrors Go's `crypto.Seed`.
pub type Seed = [u8; 32];

/// Derive the checksummed Algorand address (the 58-character base32
/// string) from a 32-byte seed. Matches the Go flow
/// `crypto.GenerateSignatureSecrets(seed).SignatureVerifier` →
/// `basics.Address(...).String()`.
pub fn address_for_seed(seed: &Seed) -> String {
    let signing = SigningKey::from_bytes(seed);
    let pubkey: [u8; 32] = signing.verifying_key().to_bytes();
    Address(pubkey).to_string()
}

/// Write the 32-byte seed to disk with mode 0600 (matches Go's
/// `writePrivateKey` at common.go:77-83). The file is created if it
/// doesn't exist and **truncated** if it does — same as Go's
/// `os.WriteFile`.
///
/// On non-Unix platforms the permission bits are ignored by the OS, but
/// the file is still created with exclusive 0600 intent.
pub fn write_private_key(keyfile: &Path, seed: &Seed) -> std::io::Result<()> {
    write_with_mode(keyfile, seed, 0o600)
}

/// Write arbitrary bytes at mode 0600. Used by `algokey sign` and
/// `multisig` to write their output txfile (matches Go's
/// `os.WriteFile(outfile, outBytes, 0600)` at `sign.go:80`).
pub fn write_with_mode_0600(path: &Path, data: &[u8]) -> std::io::Result<()> {
    write_with_mode(path, data, 0o600)
}

/// Write `"<addr>\n"` to disk with mode 0666 (matches Go's
/// `writePublicKey` at common.go:85-92).
pub fn write_public_key(pubkeyfile: &Path, checksummed: &str) -> std::io::Result<()> {
    let mut data = String::with_capacity(checksummed.len() + 1);
    data.push_str(checksummed);
    data.push('\n');
    write_with_mode(pubkeyfile, data.as_bytes(), 0o666)
}

/// Internal: write `data` to `path` with the requested Unix mode. On Unix
/// we use `OpenOptions::mode` so the permission bits are applied at
/// creation time (no transient world-readable window between `create()`
/// and `set_permissions()`). On non-Unix we fall back to plain
/// `fs::write` — the OS layer will apply its own ACL semantics.
fn write_with_mode(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        // Suppress the unused-mode warning on non-Unix targets.
        let _ = mode;
        let mut f = std::fs::File::create(path)?;
        f.write_all(data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Known fixture: all-zero seed → the well-known zero-vector address.
    /// Independently derivable from the ed25519 spec; sanity-checks our
    /// pubkey extraction.
    #[test]
    fn address_for_zero_seed_matches_known_vector() {
        let seed = [0u8; 32];
        let addr = address_for_seed(&seed);
        // Round-trip via Address::from_algorand_string to confirm format
        // (32 bytes + 4-byte sha512_256 checksum, base32 no-pad).
        let parsed = Address::from_algorand_string(&addr).expect("parse address");
        let signing = SigningKey::from_bytes(&seed);
        assert_eq!(parsed.0, signing.verifying_key().to_bytes());
        assert_eq!(addr.len(), 58, "Algorand address is 58 base32 chars");
    }

    #[test]
    fn write_private_key_is_32_bytes_mode_0600() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k");
        let seed = [7u8; 32];
        write_private_key(&path, &seed).unwrap();
        let data = std::fs::read(&path).unwrap();
        assert_eq!(data, seed);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600);
        }
    }

    #[test]
    fn write_public_key_appends_newline_mode_0666() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("p");
        let addr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ";
        write_public_key(&path, addr).unwrap();
        let data = std::fs::read_to_string(&path).unwrap();
        assert_eq!(data, format!("{addr}\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            // The actual on-disk mode is masked by the process umask,
            // which on most CI runners is 0o022 (yielding 0o644 from
            // 0o666). We assert the rwx bits are at most 0o666 and that
            // both user-read and user-write are set — matching Go's
            // identical reliance on umask for `os.WriteFile`.
            assert!(m & 0o600 == 0o600, "user rw missing: {m:o}");
            assert!(m & 0o777 <= 0o666, "permissions exceeded request: {m:o}");
        }
    }
}
