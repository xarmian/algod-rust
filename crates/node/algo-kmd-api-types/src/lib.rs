//! `algo-kmd-api-types` — on-wire JSON shapes for the kmd v1 REST API.
//!
//! Ported from `../go-algorand/daemon/kmd/lib/kmdapi/{common,requests,responses}.go`
//! (v4.5.1-stable). The shapes are decoupled from the `algo-kmd` server library
//! so a future Rust SDK (or any external HTTP consumer) can talk to a kmd server
//! without dragging in SQLite/scrypt/etc.
//!
//! ## Wire format
//!
//! Go's kmd encodes responses with `protocol.EncodeJSON` (`go-codec` JsonHandle,
//! see `protocol/codec.go:60-66`). Concretely:
//!
//! - **Byte arrays / slices** (`[32]byte`, `[64]byte`, `[]byte`) → base64-encoded
//!   strings. We model these with the [`base64_bytes`] serde adapter on
//!   `[u8; 32]` / `[u8; 64]` / `Vec<u8>` fields.
//! - **Map keys are sorted lexically** (`Canonical=true`). serde_json doesn't sort
//!   by default; the `algo-kmd` server crate's response writer (TASK-213) will
//!   apply the canonical formatter when actually writing HTTP responses. For
//!   round-trip tests in this crate, semantic equality via `serde_json::Value`
//!   is sufficient.
//! - **Pretty-printed with 2-space indent** (`Indent=2`). Same story — handled
//!   at the server layer, not here.
//! - **Empty envelope fields are omitted** (`error: false` and `message: ""`
//!   on `APIV1ResponseEnvelope` are skipped via `_struct codec:",omitempty"`
//!   in Go). We mirror this with `#[serde(skip_serializing_if = "...")]`.
//!   Non-envelope response fields are **always** serialized — Go's nested
//!   structs (e.g. `APIV1Wallet`) lack the `_struct` directive so go-codec
//!   includes every field, even zero-valued ones.
//!
//! ## Module layout
//!
//! - [`common`] — shared types: `APIV1Wallet`, `APIV1WalletHandle`,
//!   `APIV1MasterDerivationKey`, `APIV1PrivateKey`, `APIV1PublicKey`,
//!   `APIV1ResponseEnvelope`, `MultisigSubsig`, `MultisigSig`.
//! - [`requests`] — every `APIV1*Request` shape.
//! - [`responses`] — every `APIV1*Response` shape.
//! - [`base64_bytes`] — serde adapter for byte arrays / slices.

pub mod base64_bytes;
pub mod common;
pub mod requests;
pub mod responses;

pub use common::{
    APIV1MasterDerivationKey, APIV1PrivateKey, APIV1PublicKey, APIV1ResponseEnvelope, APIV1Wallet,
    APIV1WalletHandle, MultisigSig, MultisigSubsig,
};
