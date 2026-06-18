//! Local protocol update fact family.
//!
//! Update facts are local control-plane facts. Live projection of the current
//! update fact requests the generic rebuild effect and records the release
//! marker row. Replay projection of old update facts is a no-op so historical
//! updates remain retained evidence without rerunning rebuild.

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
