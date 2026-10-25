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

//! Installing the aramidmain bundle (issue #2070). `install_consensus_overrides`
//! is a process-global write-once, so this lives in its own test binary (one
//! test, no ordering assumptions) rather than beside the pure-merge tests.

use algo_types::consensus::{
    built_in_consensus_protocols, consensus_params_for_version, install_consensus_overrides,
    preload_consensus_protocols_with_bundle,
};

const BUNDLE: &str = include_str!("../../../../bin/algod-rust/consensus/aramidmain-consensus.json");

#[test]
fn installed_bundle_makes_custom_protocols_resolvable() {
    let merged =
        preload_consensus_protocols_with_bundle(None, built_in_consensus_protocols(), Some(BUNDLE))
            .unwrap();
    install_consensus_overrides(&merged);
    let p = consensus_params_for_version("aramidmain-v1.0/3").expect("installed");
    assert_eq!(p.logic_sig_version, 12);
    assert!(consensus_params_for_version("aramidmain-v1.0/1").is_some());
}
