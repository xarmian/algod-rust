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

// Concrete `Filter` implementations bundled with the fuzzer harness.
//
// TASK-84 ships the two base filters (drop, duplicate); TASK-85 adds
// reorder + nodeCrash; issue #954 adds bandwidth-limiting,
// message-decode-caching, and regossip-elimination; later follow-ups
// port the remaining handful from `go-algorand/agreement/fuzzer/`.

pub mod bandwidth;
pub mod drop_message;
pub mod duplicate_message;
pub mod message_decoder;
pub mod message_regossip;
pub mod message_reordering;
pub mod node_crash;
