//! Key wrap fact family.
//!
//! A key wrap is deterministic shared encrypted key material for a recipient.
//! It is the raw exception to natural fact signing: projection proves the
//! signer through recipient/frontier/endpoint context instead of a signature
//! field, and duplicate production must produce the same fact id. This family
//! also owns the wrap-source coordinate scheme and the shared projection helpers
//! that recipient-key, key-request, and local-material projection consume.
//! Projection validates signer/recipient/frontier context and emits local
//! recovery facts when local recipient material is present.

pub mod api;
pub mod author;
pub mod cli;
pub mod encode;
pub mod fact;
pub mod project;
#[cfg(not(verus_keep_ghost))]
pub mod proofs;
pub mod queries;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};

pub(crate) use author::{create_validated_key_wrap_facts, unwrap_key_wrap_fact};

pub const TYPE_KEY_WRAP: u8 = encode::TYPE_KEY_WRAP;

/// Accepted key-wrap projection rows, keyed by the wrap coordinate (workspace,
/// frontier, recipient, source kind, and history address) so later wrap
/// creation and unwrapping can address them.
pub const KEY_WRAP_ROWS: TableName = TableName::new("key_wrap_rows");

pub const KEY_WRAP_COLUMNS: &[&str] = &[
    "workspace_id",
    "frontier_id",
    "recipient_key_id",
    "wrapped_secret_kind",
    "range_start",
    "range_width",
    "bit_depth",
    "fact_id_prefix",
    "key_wrap_id",
    "signer_public_key",
    "wrap",
];
pub const KEY_WRAP_KEY_COLUMNS: &[&str] = &[
    "workspace_id",
    "frontier_id",
    "recipient_key_id",
    "wrapped_secret_kind",
    "range_start",
    "range_width",
    "bit_depth",
    "fact_id_prefix",
];
pub const KEY_WRAP_TABLE: TypedTableSchema = TypedTableSchema {
    table: KEY_WRAP_ROWS,
    columns: KEY_WRAP_COLUMNS,
    key_columns: KEY_WRAP_KEY_COLUMNS,
};

pub fn key_wrap_insert(input: queries::KeyWrapRow) -> Result<TableInsert, String> {
    let wrap = &input.wrap;
    // Validates the wrap and stores canonical fact bytes for diagnostic replay.
    let wrap_bytes = encode::encode_key_wrap(wrap)?;
    Ok(KEY_WRAP_TABLE.insert(vec![
        Value::Bytes(wrap.workspace_id.to_vec()),
        Value::Bytes(wrap.frontier_id.to_vec()),
        Value::Bytes(wrap.recipient_key_id.to_vec()),
        Value::U64(u64::from(wrap.wrapped_secret_kind.as_u8())),
        Value::U64(wrap.range_start),
        Value::U64(wrap.range_width),
        Value::U64(u64::from(wrap.bit_depth)),
        Value::Bytes(wrap.fact_id_prefix.to_vec()),
        Value::Bytes(input.key_wrap_id.to_vec()),
        Value::Bytes(input.signer_public_key.to_vec()),
        Value::Bytes(wrap_bytes),
    ]))
}
