//! Sumhash-512: a subset-sum hash function matching go-algorand's `go-sumhash`.
//!
//! The hash produces 64-byte (512-bit) digests using matrix-vector multiplication
//! over GF(2^64). The matrix is derived deterministically from a seed using SHAKE256.
//! Algorand uses the seed `b"Algorand"` with parameters n=8, m=1024.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// Digest size in bytes (512 bits).
pub const SUMHASH512_DIGEST_SIZE: usize = 64;

/// Block size in bytes for Sumhash-512.
pub const SUMHASH512_BLOCK_SIZE: usize = 64;

// Internal constants: n=8 rows, m=1024 columns.
const N: usize = 8;
const M: usize = 1024;
const INPUT_LEN: usize = M / 8; // 128 bytes
const OUTPUT_LEN: usize = N * 8; // 64 bytes

/// Precomputed lookup table for fast compression: `[n][m/8][256]` of u64.
/// Dimensions: [8][128][256].
type LookupTable = Vec<Vec<[u64; 256]>>;

/// Generate the sumhash matrix from a seed using SHAKE256, matching Go's
/// `RandomMatrixFromSeed`.
///
/// The XOF input is: LE(u=64 as u16) || LE(n as u16) || LE(m as u16) || seed
fn random_matrix_from_seed(seed: &[u8], n: usize, m: usize) -> Vec<Vec<u64>> {
    let mut hasher = Shake256::default();
    // Write parameters as little-endian u16
    hasher.update(&64u16.to_le_bytes()); // u=64
    hasher.update(&(n as u16).to_le_bytes());
    hasher.update(&(m as u16).to_le_bytes());
    hasher.update(seed);

    let mut reader = hasher.finalize_xof();

    let mut matrix = vec![vec![0u64; m]; n];
    let mut buf = [0u8; 8];
    for row in matrix.iter_mut() {
        for val in row.iter_mut() {
            reader.read(&mut buf);
            *val = u64::from_le_bytes(buf);
        }
    }
    matrix
}

/// Build the lookup table from the matrix, matching Go's `Matrix.LookupTable()`.
fn build_lookup_table(matrix: &[Vec<u64>]) -> LookupTable {
    let n = matrix.len();
    let m = matrix[0].len();

    let mut table: LookupTable = Vec::with_capacity(n);
    for row in matrix.iter() {
        let num_bytes = m / 8;
        let mut byte_table = Vec::with_capacity(num_bytes);
        for j in (0..m).step_by(8) {
            let mut entry = [0u64; 256];
            for b in 0u16..256 {
                let b = b as u8;
                entry[b as usize] = sum_bits(&row[j..j + 8], b);
            }
            byte_table.push(entry);
        }
        table.push(byte_table);
    }
    table
}

/// Compute the subset-sum for 8 matrix elements selected by bits of `b`.
#[inline]
fn sum_bits(a: &[u64], b: u8) -> u64 {
    let a0 = a[0] & (u64::MAX * u64::from(b & 1));
    let a1 = a[1] & (u64::MAX * u64::from((b >> 1) & 1));
    let a2 = a[2] & (u64::MAX * u64::from((b >> 2) & 1));
    let a3 = a[3] & (u64::MAX * u64::from((b >> 3) & 1));
    let a4 = a[4] & (u64::MAX * u64::from((b >> 4) & 1));
    let a5 = a[5] & (u64::MAX * u64::from((b >> 5) & 1));
    let a6 = a[6] & (u64::MAX * u64::from((b >> 6) & 1));
    let a7 = a[7] & (u64::MAX * u64::from((b >> 7) & 1));
    a0.wrapping_add(a1)
        .wrapping_add(a2)
        .wrapping_add(a3)
        .wrapping_add(a4)
        .wrapping_add(a5)
        .wrapping_add(a6)
        .wrapping_add(a7)
}

/// Compress using the lookup table: dst = A * msg (subset-sum).
fn compress(table: &LookupTable, dst: &mut [u8], msg: &[u8]) {
    debug_assert_eq!(msg.len(), INPUT_LEN);
    debug_assert_eq!(dst.len(), OUTPUT_LEN);

    for (i, row) in table.iter().enumerate() {
        let mut x: u64 = 0;
        for (j, entry) in row.iter().enumerate() {
            x = x.wrapping_add(entry[msg[j] as usize]);
        }
        dst[8 * i..8 * i + 8].copy_from_slice(&x.to_le_bytes());
    }
}

/// A Sumhash-512 hasher, implementing a Merkle-Damgard construction over
/// the subset-sum compression function.
///
/// Use [`Sumhash512::new`] for unsalted mode (the default in Algorand) or
/// [`Sumhash512::with_salt`] for salted mode.
pub struct Sumhash512 {
    table: &'static LookupTable,
    h: [u8; OUTPUT_LEN],              // chaining value
    buf: [u8; SUMHASH512_BLOCK_SIZE], // partial block buffer
    buf_len: usize,
    total_len: u64,
    salt: Option<[u8; SUMHASH512_BLOCK_SIZE]>,
}

use std::sync::OnceLock;

static ALGORAND_TABLE: OnceLock<LookupTable> = OnceLock::new();

fn get_algorand_table() -> &'static LookupTable {
    ALGORAND_TABLE.get_or_init(|| {
        let matrix = random_matrix_from_seed(b"Algorand", N, M);
        build_lookup_table(&matrix)
    })
}

impl Sumhash512 {
    /// Create a new unsalted Sumhash-512 hasher (default Algorand mode).
    pub fn new() -> Self {
        let mut s = Self {
            table: get_algorand_table(),
            h: [0u8; OUTPUT_LEN],
            buf: [0u8; SUMHASH512_BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
            salt: None,
        };
        s.reset();
        s
    }

    /// Create a new salted Sumhash-512 hasher.
    ///
    /// # Panics
    /// Panics if `salt.len() != 64`.
    pub fn with_salt(salt: &[u8]) -> Self {
        assert_eq!(salt.len(), SUMHASH512_BLOCK_SIZE, "salt must be 64 bytes");
        let mut salt_arr = [0u8; SUMHASH512_BLOCK_SIZE];
        salt_arr.copy_from_slice(salt);
        let mut s = Self {
            table: get_algorand_table(),
            h: [0u8; OUTPUT_LEN],
            buf: [0u8; SUMHASH512_BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
            salt: Some(salt_arr),
        };
        s.reset();
        s
    }

    /// Reset the hasher to its initial state.
    pub fn reset(&mut self) {
        self.h = [0u8; OUTPUT_LEN];
        self.buf_len = 0;
        self.total_len = 0;

        if self.salt.is_some() {
            // In salted mode, write an initial block of zeros
            let zeros = [0u8; SUMHASH512_BLOCK_SIZE];
            self.write(&zeros);
        }
    }

    /// Write data into the hasher.
    pub fn write(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;

        // Fill partial buffer first
        if self.buf_len > 0 {
            let space = SUMHASH512_BLOCK_SIZE - self.buf_len;
            let n = data.len().min(space);
            self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            if self.buf_len == SUMHASH512_BLOCK_SIZE {
                let block = self.buf;
                self.compress_block(&block);
                self.buf_len = 0;
            }
            data = &data[n..];
        }

        // Process full blocks
        while data.len() >= SUMHASH512_BLOCK_SIZE {
            // Copy into a temporary to avoid borrow issues
            let mut block = [0u8; SUMHASH512_BLOCK_SIZE];
            block.copy_from_slice(&data[..SUMHASH512_BLOCK_SIZE]);
            self.compress_block(&block);
            data = &data[SUMHASH512_BLOCK_SIZE..];
        }

        // Buffer remaining
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Compress a single block, applying salt XOR if present.
    fn compress_block(&mut self, block: &[u8; SUMHASH512_BLOCK_SIZE]) {
        let mut cin = [0u8; INPUT_LEN]; // OUTPUT_LEN + BLOCK_SIZE = 128
        cin[..OUTPUT_LEN].copy_from_slice(&self.h);

        if let Some(ref salt) = self.salt {
            for i in 0..SUMHASH512_BLOCK_SIZE {
                cin[OUTPUT_LEN + i] = block[i] ^ salt[i];
            }
        } else {
            cin[OUTPUT_LEN..].copy_from_slice(block);
        }

        compress(self.table, &mut self.h, &cin);
    }

    /// Finalize the hash and return the 64-byte digest.
    pub fn finalize(&self) -> [u8; SUMHASH512_DIGEST_SIZE] {
        let mut d = self.clone_state();
        d.pad_and_finalize()
    }

    /// Finalize, appending digest to the given prefix.
    pub fn finalize_into(&self, prefix: &mut Vec<u8>) {
        let digest = self.finalize();
        prefix.extend_from_slice(&digest);
    }

    fn clone_state(&self) -> Self {
        Self {
            table: self.table,
            h: self.h,
            buf: self.buf,
            buf_len: self.buf_len,
            total_len: self.total_len,
            salt: self.salt,
        }
    }

    /// Apply MD padding and produce final digest.
    fn pad_and_finalize(&mut self) -> [u8; SUMHASH512_DIGEST_SIZE] {
        let block_size = SUMHASH512_BLOCK_SIZE as u64;
        let p = block_size - 16; // padding target offset

        let bitlen = self.total_len << 3; // total bits written

        // Padding: add 0x01 byte then zeros until P bytes mod B
        // (0x01 because sumhash reads bits in little-endian order)
        let rem = self.total_len % block_size;
        let pad_len = if rem < p {
            p - rem
        } else {
            block_size + p - rem
        };

        let mut pad = vec![0u8; pad_len as usize];
        pad[0] = 0x01;
        self.write(&pad);

        // Write 128-bit length (only lower 64 bits used)
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&bitlen.to_le_bytes());
        // upper 8 bytes stay zero
        self.write(&len_block);

        debug_assert_eq!(self.buf_len, 0, "buffer must be empty after padding");

        self.h
    }
}

impl Default for Sumhash512 {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience: compute Sumhash-512 of a byte slice in one call.
pub fn sumhash512(data: &[u8]) -> [u8; SUMHASH512_DIGEST_SIZE] {
    let mut h = Sumhash512::new();
    h.write(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors from go-sumhash sumhash512_test.go
    #[test]
    fn test_sumhash512_test_vectors() {
        let vectors: &[(&str, &str)] = &[
            (
                "",
                "591591c93181f8f90054d138d6fa85b63eeeb416e6fd201e8375ba05d3cb55391047b9b64e534042562cc61944930c0075f906f16710cdade381ee9dd47d10a0",
            ),
            (
                "a",
                "ea067eb25622c633f5ead70ab83f1d1d76a7def8d140a587cb29068b63cb6407107aceecfdffa92579ed43db1eaa5bbeb4781223a6e07dd5b5a12d5e8bde82c6",
            ),
            (
                "ab",
                "ef09d55b6add510f1706a52c4b45420a6945d0751d73b801cbc195a54bc0ade0c9ebe30e09c2c00864f2bd1692eba79500965925e2be2d1ac334425d8d343694",
            ),
            (
                "abc",
                "a8e9b8259a93b8d2557434905790114a2a2e979fbdc8aa6fd373315a322bf0920a9b49f3dc3a744d8c255c46cd50ff196415c8245cdbb2899dec453fca2ba0f4",
            ),
            (
                "abcd",
                "1d4277f17e522c4607bc2912bb0d0ac407e60e3c86e2b6c7daa99e1f740fe2b4fc928defad8e1ccc4e7d96b79896ffe086836c172a3db40a154d2229484f359b",
            ),
            (
                "You must be the change you wish to see in the world. -Mahatma Gandhi",
                "5c5f63ac24392d640e5799c4164b7cc03593feeec85844cc9691ea0612a97caabc8775482624e1cd01fb8ce1eca82a17dd9d4b73e00af4c0468fd7d8e6c2e4b5",
            ),
            (
                "I think, therefore I am. – Rene Descartes.",
                "2d4583cdb18710898c78ec6d696a86cc2a8b941bb4d512f9d46d96816d95cbe3f867c9b8bd31964406c847791f5669d60b603c9c4d69dadcb87578e613b60b7a",
            ),
        ];

        for (i, (input, expected)) in vectors.iter().enumerate() {
            let digest = sumhash512(input.as_bytes());
            let got = hex::encode(digest);
            assert_eq!(
                got, *expected,
                "test vector {i} mismatch for input {:?}",
                input
            );
        }
    }

    /// Test with 6000-byte SHAKE256-derived input (from Go test).
    #[test]
    fn test_sumhash512_large_input() {
        use sha3::digest::ExtendableOutput;

        let mut input = vec![0u8; 6000];
        let mut xof = Shake256::default();
        xof.update(b"sumhash input");
        let mut reader = xof.finalize_xof();
        reader.read(&mut input);

        let digest = sumhash512(&input);
        let expected = "43dc59ca43da473a3976a952f1c33a2b284bf858894ef7354b8fc0bae02b966391070230dd23e0713eaf012f7ad525f198341000733aa87a904f7053ce1a43c6";
        assert_eq!(hex::encode(digest), expected);
    }

    /// Test salted mode with 6000-byte input (from Go test).
    #[test]
    fn test_sumhash512_with_salt() {
        use sha3::digest::ExtendableOutput;

        let mut input = vec![0u8; 6000];
        let mut xof = Shake256::default();
        xof.update(b"sumhash input");
        let mut reader = xof.finalize_xof();
        reader.read(&mut input);

        let mut salt = vec![0u8; 64];
        let mut xof2 = Shake256::default();
        xof2.update(b"sumhash salt");
        let mut reader2 = xof2.finalize_xof();
        reader2.read(&mut salt);

        let mut h = Sumhash512::with_salt(&salt);
        h.write(&input);
        let digest = h.finalize();
        let expected = "c9be08eed13218c30f8a673f7694711d87dfec9c7b0cb1c8e18bf68420d4682530e45c1cd5d886b1c6ab44214161f06e091b0150f28374d6b5ca0c37efc2bca7";
        assert_eq!(hex::encode(digest), expected);
    }

    /// Test reset behavior (from Go test).
    #[test]
    fn test_sumhash512_reset() {
        use sha3::digest::ExtendableOutput;

        // Write some garbage first
        let mut garbage = vec![0u8; 6000];
        let mut xof = Shake256::default();
        xof.update(b"sumhash");
        let mut reader = xof.finalize_xof();
        reader.read(&mut garbage);

        let mut h = Sumhash512::new();
        h.write(&garbage);
        h.write(&garbage);

        // Now reset and write the real input
        let mut input = vec![0u8; 6000];
        let mut xof2 = Shake256::default();
        xof2.update(b"sumhash input");
        let mut reader2 = xof2.finalize_xof();
        reader2.read(&mut input);

        h.reset();
        h.write(&input);

        let digest = h.finalize();
        let expected = "43dc59ca43da473a3976a952f1c33a2b284bf858894ef7354b8fc0bae02b966391070230dd23e0713eaf012f7ad525f198341000733aa87a904f7053ce1a43c6";
        assert_eq!(hex::encode(digest), expected);
    }

    /// Test sizes match expected values.
    #[test]
    fn test_sumhash512_sizes() {
        assert_eq!(SUMHASH512_DIGEST_SIZE, 64);
        assert_eq!(SUMHASH512_BLOCK_SIZE, 64);
    }

    /// Test incremental writes produce same result as single write.
    #[test]
    fn test_sumhash512_incremental() {
        let input = b"abcd";
        let one_shot = sumhash512(input);

        let mut h = Sumhash512::new();
        h.write(b"ab");
        h.write(b"cd");
        let incremental = h.finalize();

        assert_eq!(one_shot, incremental);
    }
}
