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

//! Private networks (issue #1993, epic #1989): the port of go-algorand's
//! `netdeploy` and `gen` packages behind `goal network create|pregen|...`.
//!
//! * [`template`] -- network templates (`Genesis`, `Nodes`) and `Validate`;
//! * [`genesis_gen`] -- wallets (root + participation keys) and `genesis.json`;
//! * [`create`] -- node data directories, per-node `config.json`, `network.json`.

pub mod create;
pub mod genesis_gen;
pub mod template;

/// go's `defaultNetworkTemplate.json` (`cmd/goal`), used when `goal network
/// create` is given no `-t`.
pub const DEFAULT_NETWORK_TEMPLATE: &str = include_str!("default_template.json");
