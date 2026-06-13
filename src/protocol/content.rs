//! Content scope: fact modules.
//!
//! Content facts are the user-visible workspace data and policy: messages,
//! reactions, file metadata, file slices, deletion facts, and retention policies.
//! The modules here own both authoring flows and projection rules for materialized
//! content rows. Generic purge coordinates live in core projection context helpers.
//!
//! Most content facts are gated by auth context. Projectors
//! wait for workspace membership, signer authority, key material, deletion
//! facts, or retention policies before they publish rows. When deletion or
//! retention context matches, the target projector deletes only its own rows and
//! fact bytes. Commands should build facts through the constructors in these
//! modules; they should not update content read models directly.
//!
//! To change how content is encoded or admitted, start in the leaf module's
//! `encode.rs` and `project.rs` local decode/auth/adapt helpers.
//! To change what the CLI shows, start in `queries.rs` and the leaf `cli.rs`.

pub mod file;
pub mod file_deletion;
pub mod file_slice;
pub mod message;
pub mod message_deletion;
pub mod reaction;
pub mod retention_policy;
