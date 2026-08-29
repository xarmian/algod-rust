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

//! Parallel Falcon-1024 ephemeral key generator.
//!
//! Mirrors `../go-algorand/crypto/merklesignature/keysBuilder.go`. Splits work
//! across `available_parallelism() * 2` worker threads (matching Go's
//! `runtime.NumCPU() * 2`) and aborts the remaining workers on first error.
//!
//! Each worker draws a fresh [`FALCON_SEED_SIZE`]-byte Falcon seed from `rng`
//! (`OsRng` in the public entry point) and calls [`algo_falcon::falcon_keygen`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use algo_falcon::{falcon_keygen, FALCON_SEED_SIZE};
use rand::{rngs::OsRng, RngCore};

use super::{FalconSigner, MssError};

/// Generate `num_keys` Falcon ephemeral signers in parallel using the OS RNG.
///
/// Mirrors `merklesignature.KeysBuilder`.
pub fn keys_builder(num_keys: u64) -> Result<Vec<FalconSigner>, MssError> {
    keys_builder_with_seed_provider(num_keys, &OsRngSeedProvider)
}

/// Generate `num_keys` Falcon ephemeral signers, drawing each
/// [`FALCON_SEED_SIZE`]-byte seed from the supplied seed provider. Production
/// code uses [`keys_builder`];
/// this entry point exists so tests (and any deterministic capture tool)
/// can plumb in a reproducible seed table.
pub fn keys_builder_with_seed_provider(
    num_keys: u64,
    seeds: &dyn SeedProvider,
) -> Result<Vec<FalconSigner>, MssError> {
    if num_keys == 0 {
        return Ok(Vec::new());
    }

    // Materialize the seeds up front so worker threads only do CPU-bound work.
    // This also enforces a single, well-defined RNG-draw order (needed for
    // deterministic seed providers in tests).
    let mut seed_table: Vec<[u8; FALCON_SEED_SIZE]> = (0..num_keys as usize)
        .map(|i| seeds.seed_for(i as u64))
        .collect();

    let (per_worker, num_workers) = calculate_ranges(num_keys);
    debug_assert!(per_worker >= 1);

    // Pre-allocate placeholder signers; each worker writes its slice.
    // We use `Option<FalconSigner>` so we can detect "never written" cases
    // (would indicate a partitioning bug — only triggers in panics).
    let mut keys: Vec<Option<FalconSigner>> = (0..num_keys).map(|_| None).collect();
    let cancel = AtomicBool::new(false);
    let cancel_ref = &cancel;

    let result: Result<(), MssError> = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(num_workers as usize);
        let mut start = 0u64;
        let keys_slice: &mut [Option<FalconSigner>] = &mut keys;
        let seeds_slice: &mut [[u8; FALCON_SEED_SIZE]] = &mut seed_table;

        // Split disjoint mutable subslices for each worker so threads can
        // write without any locks.
        let mut remaining_keys: &mut [Option<FalconSigner>] = keys_slice;
        let mut remaining_seeds: &mut [[u8; FALCON_SEED_SIZE]] = seeds_slice;

        for worker_idx in 0..num_workers {
            if start >= num_keys {
                break;
            }
            // Last worker mops up the remainder (matches Go's logic at
            // keysBuilder.go: `if endIdx+numOfKeysPerRoutine > numberOfKeys`).
            let is_last = worker_idx + 1 == num_workers || start + 2 * per_worker > num_keys;
            let chunk_size = if is_last {
                num_keys - start
            } else {
                per_worker
            };
            let chunk_size_usize = chunk_size as usize;

            let (keys_chunk, rest_keys) = remaining_keys.split_at_mut(chunk_size_usize);
            let (seeds_chunk, rest_seeds) = remaining_seeds.split_at_mut(chunk_size_usize);
            remaining_keys = rest_keys;
            remaining_seeds = rest_seeds;

            handles.push(scope.spawn(move || -> Result<(), MssError> {
                for (slot, seed) in keys_chunk.iter_mut().zip(seeds_chunk.iter()) {
                    if cancel_ref.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                    let (public_key, private_key) =
                        falcon_keygen(seed).map_err(|e| MssError::FalconKeygen(format!("{e}")))?;
                    *slot = Some(FalconSigner {
                        public_key,
                        private_key,
                    });
                }
                Ok(())
            }));

            start += chunk_size;
            if start >= num_keys {
                break;
            }
        }

        // Join all and propagate first error.
        let mut first_err: Option<MssError> = None;
        for h in handles {
            match h.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    cancel_ref.store(true, Ordering::Relaxed);
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
                Err(panic) => {
                    cancel_ref.store(true, Ordering::Relaxed);
                    if first_err.is_none() {
                        first_err = Some(MssError::FalconKeygen(format!(
                            "keygen worker panicked: {panic:?}"
                        )));
                    }
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    });

    result?;

    // All slots must be Some at this point (if cancel fired, an error was
    // returned above). Unwrap into the final Vec<FalconSigner>.
    let mut out: Vec<FalconSigner> = Vec::with_capacity(num_keys as usize);
    for (i, slot) in keys.into_iter().enumerate() {
        match slot {
            Some(s) => out.push(s),
            None => {
                return Err(MssError::FalconKeygen(format!(
                    "keysBuilder: slot {i} was not populated (partition bug)"
                )))
            }
        }
    }
    Ok(out)
}

/// Compute (keys_per_worker, num_workers).
///
/// Mirrors `merklesignature.calculateRanges`:
/// - `num_workers = available_parallelism() * 2`
/// - if `num_keys > num_workers`: `keys_per_worker = num_keys / num_workers`
/// - else:                       `keys_per_worker = 1`
fn calculate_ranges(num_keys: u64) -> (u64, u64) {
    let parallelism = thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(1)
        .max(1);
    let num_workers = parallelism.saturating_mul(2).max(1);
    let per_worker = if num_keys > num_workers {
        num_keys / num_workers
    } else {
        1
    };
    (per_worker, num_workers)
}

/// Abstraction over how each worker obtains its Falcon seed bytes.
///
/// The public `keys_builder` uses [`OsRngSeedProvider`] (system entropy);
/// tests use a deterministic seed table (see
/// [`DeterministicSeedProvider`]) to verify thread-count-invariance.
pub trait SeedProvider: Sync {
    fn seed_for(&self, index: u64) -> [u8; FALCON_SEED_SIZE];
}

struct OsRngSeedProvider;

impl SeedProvider for OsRngSeedProvider {
    fn seed_for(&self, _index: u64) -> [u8; FALCON_SEED_SIZE] {
        let mut seed = [0u8; FALCON_SEED_SIZE];
        OsRng.fill_bytes(&mut seed);
        seed
    }
}

// ── Public test helpers ──────────────────────────────────────────────────
//
// Promoted out of `#[cfg(test)]` so integration tests under `tests/` and any
// deterministic fixture-capture tool can exercise reproducible keygen. They
// are not used by production code paths.

use sha2::{Digest, Sha512};

/// Deterministic seed provider: hashes `(domain_seed || index)` into
/// [`FALCON_SEED_SIZE`] bytes. Used to prove that key generation is
/// reproducible regardless of how the work is split across worker threads.
pub struct DeterministicSeedProvider {
    pub domain_seed: u64,
}

impl SeedProvider for DeterministicSeedProvider {
    fn seed_for(&self, index: u64) -> [u8; FALCON_SEED_SIZE] {
        let mut h = Sha512::new();
        h.update(b"mss-test-seed");
        h.update(self.domain_seed.to_le_bytes());
        h.update(index.to_le_bytes());
        let digest = h.finalize();
        let mut seed = [0u8; FALCON_SEED_SIZE];
        seed.copy_from_slice(&digest[..FALCON_SEED_SIZE]);
        seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculate_ranges_matches_go_semantics() {
        // num_keys ≤ num_workers ⇒ per_worker = 1
        let (per, n) = calculate_ranges(2);
        assert!(n >= 2);
        assert_eq!(per, 1);
        // num_keys > num_workers ⇒ per_worker = num_keys / num_workers
        let (per_big, n_big) = calculate_ranges(1000);
        assert_eq!(per_big, 1000 / n_big);
    }
}
