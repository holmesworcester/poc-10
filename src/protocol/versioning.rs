//! Protocol versioning fact family.
//!
//! The versioning fact family owns the local update fact, the projected release
//! marker row, command/query helpers for that marker, and state-summary query
//! diagnostics. Recurring release checks are protocol intents outside this fact
//! family; they author update facts through this family's public API.
//!
//! Keep two version concepts separate:
//!
//! 1. The release marker is stored protocol state. The recurring
//!    `check_version` intent reads that marker, compares it with the one
//!    `CURRENT_PROTOCOL_VERSION` compiled into this release, and emits a local
//!    update fact when the database needs a rebuild. The update fact is the
//!    repair trigger: its projection requests the generic rebuild effect and
//!    records the new release marker.
//!
//! 2. A projector or query storage requirement is a local safety contract for a
//!    read or write path. A fact family declares the storage version its
//!    projector and query helpers expect, usually next to `PROJECTOR_INFO` in
//!    `project.rs`; query modules import that same constant before reading
//!    materialized rows. This guard is not the release marker and it is not what
//!    triggers rebuild. It is a concurrency and replay safety hatch: normal work
//!    must not consume queue rows or read materialized tables under a storage
//!    shape it did not declare.
//!
//! A given checkout/release carries one protocol version. The protocol code does
//! not contain a live matrix of release versions. Compatibility with older
//! retained facts or older materialized storage belongs in the owning
//! projector/query code that needs it. During an update, that code may read old
//! storage shapes only to derive the current release's state; it must write only
//! the current release's declared tables and effects, never old database tables.
//!
//! Core should remain mechanical here. It may enforce a declared storage
//! requirement at an atomic commit boundary, but protocol modules own the version
//! numbers, the release marker, the recurring check, the update fact, and the
//! per-family compatibility rules.
//!
//! The release rule is deliberately outside core: do not ship code that authors
//! a new durable fact type until every non-deprecated release can decode,
//! authenticate, validate, and project that type. After that release discipline,
//! the local storage marker plus per-route storage guards cover the rest.

pub mod api;
pub mod author;
pub mod cli;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::db::{TableName, TypedTableSchema};

pub use api::{author_update, UpdateReceipt};
pub use author::update_fact;
pub use cli::update_output;
pub use encode::{
    decode_update_fact, encode_update_fact, TYPE_VERSIONING_UPDATE, UPDATE_FACT_BYTES,
};
pub use fact::UpdateFact;
pub use project::{authenticate, UpdateProjector, PROJECTOR_INFO, STORAGE_REQUIREMENT};
pub use queries::{
    current_version, ensure_storage_ready, require_storage_requirement, require_storage_version,
    storage_ready, VersionRow,
};

pub const CURRENT_PROTOCOL_VERSION: u32 = 1;

pub const PROTOCOL_VERSION_ROWS: TableName = TableName::new("protocol_version_rows");
pub const PROTOCOL_VERSION_COLUMNS: &[&str] =
    &["update_fact_id", "protocol_version", "applied_at_ms"];
pub const PROTOCOL_VERSION_KEY_COLUMNS: &[&str] = &["update_fact_id"];
pub const PROTOCOL_VERSION_TABLE: TypedTableSchema = TypedTableSchema {
    table: PROTOCOL_VERSION_ROWS,
    columns: PROTOCOL_VERSION_COLUMNS,
    key_columns: PROTOCOL_VERSION_KEY_COLUMNS,
};
