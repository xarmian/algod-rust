//! Algorand 25-word mnemonic encoding.
//!
//! Byte-for-byte compatible with go-algorand's `crypto/passphrase` package
//! (v4.6.0-stable). A 32-byte key encodes as 24 wordlist words (11 bits
//! each, packed little-endian) followed by an 11-bit SHA-512/256 checksum
//! word, for 25 space-separated words total.
//!
//! Reference: `../go-algorand/crypto/passphrase/passphrase.go`.
//!
//! ## Conformance notes
//!
//! - Checksum hash is **SHA-512/256** (`crypto/sha512.Sum512_256`), not
//!   plain SHA-512. The first two bytes of the digest are interpreted via
//!   the same little-endian 11-bit packing as the key bytes; the lowest 11
//!   bits index into the wordlist to produce the checksum word.
//! - Decoding tolerates runs of whitespace and leading/trailing space
//!   (matches Go's `strings.Split` + empty-word filter).
//! - Wrong-length input, unknown words, and bad checksums all return typed
//!   errors mirroring `errors.go`.

mod wordlist;

use std::collections::HashMap;
use std::sync::OnceLock;

use sha2::{Digest, Sha512_256};
use thiserror::Error;

use self::wordlist::{wordlist, WORDLIST_RAW};

/// Each wordlist word represents this many bits.
const BITS_PER_WORD: u32 = 11;
/// Reserved for the final checksum word.
const CHECKSUM_LEN_BITS: u32 = 11;
/// Key length in bytes (matches `keyLenBytes` in Go).
const KEY_LEN_BYTES: usize = 32;
/// Total mnemonic length in words (matches `mnemonicLenWords` in Go).
const MNEMONIC_LEN_WORDS: usize = 25;

// Compile-time sanity check matching Go's `init()` invariant
// (passphrase.go:37-40):
//     mnemonicLenWords*bitsPerWord - checksumLenBits == keyLenBytes*8 + paddingZeros
// with paddingZeros = bitsPerWord - ((keyLenBytes*8) % bitsPerWord) = 3.
const _: () = {
    let padding_zeros = BITS_PER_WORD as usize - ((KEY_LEN_BYTES * 8) % BITS_PER_WORD as usize);
    assert!(
        MNEMONIC_LEN_WORDS * BITS_PER_WORD as usize - CHECKSUM_LEN_BITS as usize
            == KEY_LEN_BYTES * 8 + padding_zeros,
        "passphrase: invalid constants"
    );
};

/// Errors returned by [`key_to_mnemonic`] and [`mnemonic_to_key`].
///
/// Variant names and messages mirror `errors.go` so operator-facing output
/// matches what go-algorand prints.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PassphraseError {
    /// Key buffer was not exactly 32 bytes.
    #[error("key length must be {} bytes", KEY_LEN_BYTES)]
    WrongKeyLen,
    /// Mnemonic did not contain exactly 25 words after whitespace collapse.
    #[error("mnemonic must be {} words", MNEMONIC_LEN_WORDS)]
    WrongMnemonicLen,
    /// One of the mnemonic words is not in the Algorand 2,048-word list.
    #[error("{0} is not in the words list")]
    WordNotInList(String),
    /// The 11-bit checksum did not match (corrupted or tampered mnemonic).
    #[error("checksum failed to validate")]
    WrongChecksum,
}

/// Encode a 32-byte key as a 25-word Algorand mnemonic.
///
/// Returns `Err(PassphraseError::WrongKeyLen)` if `key.len() != 32`.
pub fn key_to_mnemonic(key: &[u8]) -> Result<String, PassphraseError> {
    if key.len() != KEY_LEN_BYTES {
        return Err(PassphraseError::WrongKeyLen);
    }
    let chk = checksum_word(key);
    let uint11 = to_uint11_array(key);
    let words = wordlist();
    let mut out = String::with_capacity(MNEMONIC_LEN_WORDS * 8);
    for (i, idx) in uint11.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(words[*idx as usize]);
    }
    out.push(' ');
    out.push_str(chk);
    Ok(out)
}

/// Decode a 25-word Algorand mnemonic back into the 32-byte key.
///
/// Mirrors `MnemonicToKey` (passphrase.go:60-128). Tolerates extra
/// whitespace; rejects wrong-length, unknown-word, and bad-checksum input.
pub fn mnemonic_to_key(mnemonic: &str) -> Result<[u8; KEY_LEN_BYTES], PassphraseError> {
    // Match Go: split on single ASCII space, then filter empties. This is
    // identical to `strings.Split(mnemonic, " ")` + the empty-filter loop at
    // passphrase.go:67-74. (It is NOT the same as splitting on Unicode
    // whitespace — go-algorand only collapses ASCII spaces.)
    let words: Vec<&str> = mnemonic.split(' ').filter(|w| !w.is_empty()).collect();

    if words.len() != MNEMONIC_LEN_WORDS {
        return Err(PassphraseError::WrongMnemonicLen);
    }

    let index = word_index_map();
    for w in &words {
        if !index.contains_key(*w) {
            return Err(PassphraseError::WordNotInList((*w).to_string()));
        }
    }

    // Convert the first 24 words (excluding checksum) into 11-bit values.
    let uint11: Vec<u32> = words[..MNEMONIC_LEN_WORDS - 1]
        .iter()
        .map(|w| index[*w] as u32)
        .collect();

    let byte_arr = to_byte_array(&uint11);

    // Expect 33 bytes: 32 key bytes + 1 padding byte that must be zero.
    // This mirrors passphrase.go:103-112 exactly.
    if byte_arr.len() != KEY_LEN_BYTES + 1 {
        return Err(PassphraseError::WrongKeyLen);
    }
    if byte_arr[KEY_LEN_BYTES] != 0 {
        return Err(PassphraseError::WrongChecksum);
    }

    let mut key = [0u8; KEY_LEN_BYTES];
    key.copy_from_slice(&byte_arr[..KEY_LEN_BYTES]);

    let expected_chk = checksum_word(&key);
    let provided_chk = words[MNEMONIC_LEN_WORDS - 1];
    if expected_chk != provided_chk {
        return Err(PassphraseError::WrongChecksum);
    }

    Ok(key)
}

/// 11-bit checksum word — `wordlist[first_11_bits_LE(SHA512_256(data)[:2])]`.
///
/// Matches `checksum` in passphrase.go:202-211.
fn checksum_word(data: &[u8]) -> &'static str {
    let mut hasher = Sha512_256::new();
    hasher.update(data);
    let full = hasher.finalize();
    let chk_bytes = &full[..2];
    let arr = to_uint11_array(chk_bytes);
    wordlist()[arr[0] as usize]
}

/// Pack a byte slice into 11-bit little-endian groups.
///
/// Mirrors `toUint11Array` in passphrase.go:131-157 — including the
/// final-partial-group flush.
fn to_uint11_array(arr: &[u8]) -> Vec<u32> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(arr.len() * 8 / BITS_PER_WORD as usize + 2);
    for &byte in arr {
        buffer |= (byte as u32) << bits;
        bits += 8;
        if bits >= BITS_PER_WORD {
            out.push(buffer & 0x7ff);
            buffer >>= BITS_PER_WORD;
            bits -= BITS_PER_WORD;
        }
    }
    if bits != 0 {
        out.push(buffer & 0x7ff);
    }
    out
}

/// Unpack 11-bit little-endian groups back into bytes.
///
/// Mirrors `toByteArray` in passphrase.go:161-182 — including the final
/// trailing-byte flush that yields an "extra empty byte" for inputs whose
/// total bit count isn't a multiple of 8. The padding byte is later
/// validated as zero in [`mnemonic_to_key`].
fn to_byte_array(arr: &[u32]) -> Vec<u8> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(arr.len() * BITS_PER_WORD as usize / 8 + 2);
    for &v in arr {
        buffer |= v << bits;
        bits += BITS_PER_WORD;
        while bits >= 8 {
            out.push((buffer & 0xff) as u8);
            buffer >>= 8;
            bits -= 8;
        }
    }
    if bits != 0 {
        out.push(buffer as u8);
    }
    out
}

/// Reverse-index lookup table — word → wordlist position. Computed once.
fn word_index_map() -> &'static HashMap<&'static str, u16> {
    static MAP: OnceLock<HashMap<&'static str, u16>> = OnceLock::new();
    MAP.get_or_init(|| {
        wordlist()
            .iter()
            .enumerate()
            .map(|(i, w)| (*w, i as u16))
            .collect()
    })
}

/// Public re-export so callers can verify wordlist integrity at startup if
/// they wish (matches the `wordlistChecksum` constant in Go).
#[doc(hidden)]
pub fn _wordlist_checksum_word() -> &'static str {
    checksum_word(WORDLIST_RAW.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors Go's `TestZeroVector` (passphrase_test.go:47-57).
    #[test]
    fn zero_vector() {
        let key = [0u8; 32];
        let expected = "abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon abandon abandon \
            invest";
        let m = key_to_mnemonic(&key).unwrap();
        assert_eq!(m, expected);
        assert_eq!(mnemonic_to_key(&m).unwrap(), key);
    }

    /// Wordlist hasn't been corrupted — mirrors Go's init-time assertion
    /// (`wordlistChecksum == "venue"`).
    #[test]
    fn wordlist_checksum_is_venue() {
        assert_eq!(_wordlist_checksum_word(), "venue");
    }

    /// Mirrors Go's `TestGenerateAndRecovery` (1,000 random round-trips).
    #[test]
    fn round_trip_random() {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut key = [0u8; 32];
        for _ in 0..1_000 {
            rng.fill_bytes(&mut key);
            let m = key_to_mnemonic(&key).unwrap();
            let recovered = mnemonic_to_key(&m).unwrap();
            assert_eq!(recovered, key);
        }
    }

    /// Wrong key lengths must error (mirrors `TestInvalidKeyLen`).
    #[test]
    fn invalid_key_len() {
        for bad in [0usize, 1, 31, 33, 64, 100] {
            let key = vec![0u8; bad];
            assert_eq!(key_to_mnemonic(&key), Err(PassphraseError::WrongKeyLen));
        }
    }

    /// Unknown words must error (mirrors `TestWordNotInList`).
    #[test]
    fn word_not_in_list() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon abandon zzz invest";
        match mnemonic_to_key(bad) {
            Err(PassphraseError::WordNotInList(w)) => assert_eq!(w, "zzz"),
            other => panic!("expected WordNotInList, got {other:?}"),
        }
    }

    /// Corrupted checksum must error (mirrors `TestCorruptedChecksum`).
    #[test]
    fn corrupted_checksum() {
        let key = [7u8; 32];
        let m = key_to_mnemonic(&key).unwrap();
        let mut parts: Vec<&str> = m.split(' ').collect();
        // Replace the checksum word with the next word in the list.
        let last = parts.last().copied().unwrap();
        let words = wordlist();
        let idx = word_index_map()[last];
        let next = words[(idx as usize + 1) % words.len()];
        *parts.last_mut().unwrap() = next;
        let tampered = parts.join(" ");
        assert_eq!(
            mnemonic_to_key(&tampered),
            Err(PassphraseError::WrongChecksum)
        );
    }

    /// Wrong-length mnemonics must error (extra and missing words).
    #[test]
    fn wrong_mnemonic_len() {
        let short = "abandon abandon abandon";
        assert_eq!(
            mnemonic_to_key(short),
            Err(PassphraseError::WrongMnemonicLen)
        );
        let long = (0..26).map(|_| "abandon").collect::<Vec<_>>().join(" ");
        assert_eq!(
            mnemonic_to_key(&long),
            Err(PassphraseError::WrongMnemonicLen)
        );
    }

    /// Extra whitespace between words must be tolerated (matches Go's
    /// strings.Split + empty-filter behaviour).
    #[test]
    fn tolerates_extra_whitespace() {
        let key = [0u8; 32];
        let m = key_to_mnemonic(&key).unwrap();
        // Insert double spaces and add leading + trailing whitespace.
        let mangled = format!("  {}  ", m.replace(' ', "  "));
        assert_eq!(mnemonic_to_key(&mangled).unwrap(), key);
    }

    /// `toUint11Array` / `toByteArray` round-trip (mirrors Go's
    /// `TestUint11Array` shape but scaled down).
    #[test]
    fn uint11_round_trip() {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        for len in [0usize, 1, 7, 11, 16, 32, 33, 64, 100] {
            let mut a = vec![0u8; len];
            rng.fill_bytes(&mut a);
            let packed = to_uint11_array(&a);
            let unpacked = to_byte_array(&packed);
            // Mirrors Go: c may be a.len(), a.len()+1, or a.len()+2 — the
            // trailing groups can flush an extra padding byte beyond the
            // already-expected +1 (passphrase_test.go:107).
            assert!(
                unpacked.len() == a.len()
                    || unpacked.len() == a.len() + 1
                    || unpacked.len() == a.len() + 2
            );
            assert_eq!(&unpacked[..a.len()], a.as_slice());
        }
    }
}
