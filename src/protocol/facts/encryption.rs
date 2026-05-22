//! Encryption and retention fact modules.
//!
//! Encryption facts describe recipient keys, key wraps, local key material,
//! removal frontiers, local history-node secrets, key requests, and disappearing
//! message settings. Together they decide when content can be opened, when
//! deleted or expired material should be purged, and which key material can be
//! shared with another endpoint.
//!
//! The boundary is intentionally split. Layout and fact modules define stable
//! bytes. `project.rs` dispatches encryption-family projection to focused
//! helpers that check context and publish rows/offers. `commands.rs` and
//! `create.rs` build user-initiated facts. Intent modules perform delayed work
//! such as creating key wraps, unwrapping received wraps, and purging retired
//! material.
//!
//! Add new encryption policy here when it affects key material, retention, or
//! encryption-derived context. Content modules should ask for encryption
//! context and rows; they should not reconstruct key-eligibility rules.

pub mod cli;
pub mod commands;
pub mod coverage;
pub mod create;
pub mod disappearing_messages_setting;
pub mod fact;
pub mod intent;
mod key_request;
pub mod layout;
pub mod local_history_node_secret;
mod local_material;
mod local_recipient_key;
pub mod project;
mod recipient_key;
pub mod removal_frontier;
pub mod rows;
mod signed_key_wrap;
mod validation;
pub mod wrap_source;
