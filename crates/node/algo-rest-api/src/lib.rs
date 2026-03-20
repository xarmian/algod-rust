//! Algorand REST API server crate.
//!
//! Provides the HTTP REST API that mirrors go-algorand's `algod` API surface,
//! including `/versions`, `/v2/status`, `/v2/transactions/params`, and more.

pub mod abi;
pub mod auth;
pub mod box_name;
pub mod error;
pub mod format;
pub mod handlers;
pub mod models;
pub mod node;
pub mod router;
pub mod server;

// Re-export key types for convenience.
pub use error::ErrorResponse;
pub use format::ResponseFormat;
pub use node::{BuildVersion, NodeInterface, NodeStatus, ProtocolSwitchInfo};
pub use router::TokenConfig;
pub use server::{ApiServer, ApiServerConfig};
