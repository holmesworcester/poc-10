//! Content scope: fact and intent modules.
//!
//! Content facts are the user-visible workspace data: messages, reactions,
//! file metadata, file slices, generic content events, and tombstones. The
//! modules here own both authoring flows and projection rules for materialized
//! content rows.
//!
//! Most content facts are gated by identity and encryption context. Projectors
//! wait for workspace membership, signer authority, key material, deletion
//! facts, or retention settings before they publish rows. Commands should build
//! facts through the constructors in these modules; they should not update
//! content read models directly.
//!
//! To change how content is encoded or admitted, start in the leaf module's
//! `layout.rs` and `project.rs`. To change what the CLI shows, start in
//! `queries.rs` and the leaf `cli.rs`.

pub mod event;
pub mod file;
pub mod file_deletion;
pub mod file_slice;
pub mod message;
pub mod message_deletion;
pub mod reaction;

// Intents: delayed cleanup after projection establishes that a message, file,
// reaction, or retention range should disappear from rows or stored facts.
pub mod purge_below_retention_floor;
pub mod purge_deleted_message;
pub mod purge_expired_message;
pub mod purge_message_child;
