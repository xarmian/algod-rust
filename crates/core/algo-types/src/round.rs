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

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(transparent)]
pub struct Round(pub u64);

impl Round {
    pub fn next(self) -> Self {
        Round(self.0 + 1)
    }

    pub fn prev(self) -> Self {
        Round(self.0.saturating_sub(1))
    }

    /// Subtract `amount` rounds with saturation arithmetic — returns `Round(0)`
    /// on underflow instead of wrapping.  Matches Go's `Round.SubSaturate`.
    pub fn sub_saturate(self, amount: u64) -> Self {
        Round(self.0.saturating_sub(amount))
    }
}

impl fmt::Display for Round {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for Round {
    fn from(v: u64) -> Self {
        Round(v)
    }
}

impl From<Round> for u64 {
    fn from(r: Round) -> u64 {
        r.0
    }
}
