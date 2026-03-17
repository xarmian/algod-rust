//! Consensus-layer cryptographic primitives for algod-rust.
//!
//! This crate provides:
//! - **VRF** (Verifiable Random Function) prove/verify operations needed for
//!   Algorand consensus participation, following ECVRF-ED25519-SHA512-Elligator2
//!   (draft-irtf-cfrg-vrf-03).
//! - **One-time signatures (OTS)** — a two-level ed25519 ephemeral key tree
//!   with forward-secure deletion, matching go-algorand's `crypto/onetimesig.go`.
//! - **Sortition** — VRF-based committee selection.

pub mod merklearray;
pub mod merklesig;
pub mod onetimesig;
pub mod sortition;
pub mod sumhash;
pub mod vrf;

pub use onetimesig::{
    one_time_id_for_round, verify_one_time_signature, OneTimeSignature, OneTimeSignatureIdentifier,
    OneTimeSignatureSecrets, OneTimeSignatureSubkeyBatchID, OneTimeSignatureSubkeyOffsetID,
};
pub use vrf::{VrfKeypair, VrfOutput, VrfPrivkey, VrfProof, VrfPubkey};
