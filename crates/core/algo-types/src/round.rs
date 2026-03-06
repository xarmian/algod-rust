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
