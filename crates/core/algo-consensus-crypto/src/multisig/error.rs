//! Typed errors for the `multisig` module. Variant names and Display
//! strings mirror `../go-algorand/crypto/multisig.go` so operator
//! tooling (CLI grep, logs, dashboards) sees identical wording across
//! Rust and Go.
//!
//! Reference: `../go-algorand/crypto/util.go` (the `errInvalid*`
//! constants exported by package crypto).

use thiserror::Error;

/// All multisig-producer-side failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// `version != 1`. Matches Go's `errUnknownVersion`.
    #[error("unknown multisig version")]
    UnknownVersion,
    /// `threshold == 0`, `pks.len() == 0`, or `threshold > pks.len()`.
    /// Matches Go's `errInvalidThreshold`.
    #[error("invalid multisig threshold")]
    InvalidThreshold,
    /// More than 255 public keys (would overflow Go's `uint8` count
    /// and exceeds `maxMultisig`).
    #[error("too many multisig public keys (max 255)")]
    TooManyKeys,
    /// Caller-supplied signer doesn't appear in the public-key list.
    /// Matches Go's `errKeyNotExist`.
    #[error("signing key not found in multisig public-key list")]
    KeyNotExist,
    /// `multisig_assemble` was called with fewer than 2 partials.
    /// Matches Go's `errors.New("invalid number of signatures to assemble")`.
    #[error("invalid number of signatures to assemble")]
    InvalidNumberOfSignatures,
    /// Two preimages being assembled disagree on the threshold.
    #[error("multisig thresholds do not match")]
    ThresholdsDoNotMatch,
    /// Two preimages being assembled disagree on the version.
    #[error("multisig versions do not match")]
    VersionsDoNotMatch,
    /// Two preimages being assembled disagree on subsig count.
    #[error("multisig subsig count differs across partials")]
    SubsigCountDiffers,
    /// Two preimages being assembled disagree on a public key.
    #[error("multisig public keys do not match across partials")]
    KeysDoNotMatch,
}
