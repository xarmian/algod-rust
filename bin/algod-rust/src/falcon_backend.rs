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

//! Applies `config.json`'s `FalconBackend` to the process.
//!
//! DIVERGENCE DIV-001: go-algorand has exactly one Falcon implementation (the
//! C library via cgo). algod-rust has two (`algo_falcon::FalconBackend`) and
//! this is where the operator's choice becomes the process-wide backend —
//! once, right after `config.json` is loaded and before any ledger,
//! state-proof or AVM code can run a Falcon operation. See
//! `docs/DIVERGENCES.md`.

use anyhow::anyhow;

/// Parse `cfg.falcon_backend` and pin it as the process-wide backend.
///
/// Fails (and the command must not continue) when the value is not a
/// backend this build knows — including `"c"` in a build made without the
/// `falcon-c-backend` feature — or when a Falcon operation already ran and
/// pinned a different backend, so the node never silently runs anything
/// other than what its configuration asks for.
pub fn apply_falcon_backend(cfg: &algo_config::Local) -> anyhow::Result<()> {
    let backend: algo_falcon::FalconBackend = cfg
        .falcon_backend
        .parse()
        .map_err(|e| anyhow!("config.json FalconBackend: {e}"))?;
    match algo_falcon::set_falcon_backend(backend) {
        Ok(()) => {
            tracing::info!(falcon_backend = %backend, "falcon-1024 backend selected");
            Ok(())
        }
        Err(current) => Err(anyhow!(
            "config.json asks for FalconBackend {backend:?} but this process already pinned \
             {current:?} (a falcon operation ran before the configuration was applied)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_applies_cleanly_and_matches_the_crate_default() {
        apply_falcon_backend(&algo_config::Local::default()).expect("default backend applies");
        assert_eq!(
            algo_falcon::falcon_backend(),
            algo_falcon::FalconBackend::default()
        );
        // Idempotent: applying the same configuration again is fine.
        apply_falcon_backend(&algo_config::Local::default()).expect("re-apply is a no-op");
    }

    #[test]
    fn unknown_backend_name_is_a_startup_error() {
        let cfg = algo_config::Local {
            falcon_backend: "emulated".to_string(),
            ..algo_config::Local::default()
        };
        let err = apply_falcon_backend(&cfg).unwrap_err().to_string();
        assert!(err.contains("FalconBackend"), "{err}");
        assert!(err.contains("emulated"), "{err}");
    }
}
