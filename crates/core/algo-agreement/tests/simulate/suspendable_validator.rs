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

// A `BlockValidator` whose `validate()` call can be suspended (blocked) and
// later resumed by the test driver.
//
// Mirrors go-algorand's `testSuspendableBlockValidator`
// (`agreement/service_test.go`), used exclusively by
// `TestAgreementRegression_WrongPeriodPayloadVerificationCancellation_8ba23942`
// to pin proposal-verification worker threads in place so the test can
// control precisely when a stale-period payload's verification completes
// relative to the network entering a new period. Go's version blocks on
// `<-ch` where `ch` is a channel that `suspend()` replaces with a fresh
// (open) one and `resume()`-equivalent (`close(v.x)`, called directly by
// the test via the channel `suspend()` returns) closes to release every
// blocked goroutine at once. This port uses `crossbeam_channel` for the
// same "closing releases every waiter" semantics: dropping every `Sender`
// clone makes every clone of the paired `Receiver` observe `Disconnected`
// on `recv()`.

use std::sync::{Arc, Mutex};

use algo_agreement::stubs::StubValidatedBlock;
use algo_agreement::traits::{AgreementError, BlockValidator, ValidatedBlock};
use algo_types::Block;

struct Gate {
    /// Kept alive only to control when the gate opens: dropped (by
    /// `resume()`, or replaced by the next `suspend()`) to release every
    /// `Receiver::recv()` currently blocked on `rx`.
    _tx: Option<crossbeam_channel::Sender<()>>,
    rx: crossbeam_channel::Receiver<()>,
}

/// `BlockValidator` that accepts every block (like
/// [`StubBlockValidator::accepting`](algo_agreement::stubs::StubBlockValidator::accepting))
/// but only after passing through the current suspension gate.
///
/// `Clone`s share the same underlying gate (via the inner `Arc`) — needed
/// so ONE driver-held handle can `suspend()`/`resume()` the SAME gate every
/// per-node `Parameters::block_validator` clone and every per-node
/// `AsyncCryptoVerifier`'s internal `Arc<BV>` clone are blocking on,
/// mirroring go's `setupAgreementWithValidator`, which hands the identical
/// single `BlockValidator` instance to every node's `Parameters` AND to the
/// shared `testingNetwork` — a genuinely global, cluster-wide suspend
/// switch, not a per-node one.
#[derive(Clone)]
pub struct SuspendableBlockValidator {
    gate: Arc<Mutex<Gate>>,
}

impl SuspendableBlockValidator {
    /// A validator that starts unsuspended — `validate()` returns
    /// immediately, matching go's `makeTestSuspendableBlockValidator`
    /// (which starts with an already-closed channel).
    pub fn new() -> Self {
        let (tx, rx) = crossbeam_channel::bounded::<()>(0);
        drop(tx); // already "closed": recv() returns Disconnected immediately.
        Self {
            gate: Arc::new(Mutex::new(Gate { _tx: None, rx })),
        }
    }

    /// Arm a fresh suspension: every `validate()` call made from now on
    /// (on this handle or any clone) blocks until the next [`Self::resume`].
    /// Mirrors go's `suspend()`.
    pub fn suspend(&self) {
        let (tx, rx) = crossbeam_channel::bounded::<()>(0);
        let mut guard = self.gate.lock().unwrap();
        *guard = Gate { _tx: Some(tx), rx };
    }

    /// Release every `validate()` call currently blocked on the gate armed
    /// by the most recent [`Self::suspend`] (and let future calls pass
    /// through immediately, until the next `suspend()`). Mirrors go's
    /// `close(ch)`.
    pub fn resume(&self) {
        let mut guard = self.gate.lock().unwrap();
        guard._tx = None;
    }
}

impl Default for SuspendableBlockValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockValidator for SuspendableBlockValidator {
    fn validate(&self, block: &Block) -> Result<Box<dyn ValidatedBlock>, AgreementError> {
        // Clone the receiver out from under the mutex before blocking, so
        // `suspend()`/`resume()` remain callable concurrently from the
        // driver thread while N worker threads sit here.
        let rx = self.gate.lock().unwrap().rx.clone();
        let _ = rx.recv();
        Ok(Box::new(StubValidatedBlock {
            block: block.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    fn make_block() -> Block {
        Block::default()
    }

    #[test]
    fn unsuspended_validator_returns_immediately() {
        let v = SuspendableBlockValidator::new();
        let block = make_block();
        let result = v.validate(&block);
        assert!(result.is_ok());
    }

    #[test]
    fn suspended_validator_blocks_until_resumed() {
        let v = Arc::new(SuspendableBlockValidator::new());
        v.suspend();

        let v2 = Arc::clone(&v);
        let handle = std::thread::spawn(move || {
            let block = make_block();
            v2.validate(&block)
        });

        // Give the worker time to actually park on the gate.
        std::thread::sleep(Duration::from_millis(50));
        assert!(!handle.is_finished());

        v.resume();
        let result = handle.join().unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn resume_releases_multiple_waiters_at_once() {
        let v = Arc::new(SuspendableBlockValidator::new());
        v.suspend();

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let v2 = Arc::clone(&v);
                std::thread::spawn(move || v2.validate(&make_block()))
            })
            .collect();

        std::thread::sleep(Duration::from_millis(50));
        assert!(handles.iter().all(|h| !h.is_finished()));

        v.resume();
        for h in handles {
            assert!(h.join().unwrap().is_ok());
        }
    }
}
