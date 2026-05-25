//! Per-group subcommand enums. Each module mirrors one of Go's
//! `cmd/goal/<group>.go` files — leaf list, naming, and `Short` text
//! come straight from the corresponding cobra `Use` / `Short` fields.

pub mod account;
pub mod app;
pub mod asset;
pub mod clerk;
pub mod completion;
pub mod kmd;
pub mod ledger;
pub mod network;
pub mod node;
pub mod wallet;
