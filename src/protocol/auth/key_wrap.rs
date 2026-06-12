//! Key wrap fact family.
//!
//! A key wrap is deterministic shared encrypted key material for a recipient.
//! It is the raw exception to natural fact signing: projection proves the
//! signer through recipient/frontier/endpoint context instead of a signature
//! field, and duplicate production must produce the same fact id. This family
//! also owns the wrap-source
//! coordinate scheme and the shared projection helpers that recipient-key,
//! key-request, and local-material projection consume. Projection validates
//! signer/recipient/frontier context and emits unwrap work when local recipient
//! material is present.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod cli;
pub mod commands;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

pub const TYPE_KEY_WRAP: u8 = encode::TYPE_KEY_WRAP;

/// Accepted key-wrap projection rows, keyed by the wrap coordinate (workspace,
/// frontier, recipient, source kind, and history address) so later wrap
/// creation and unwrapping can address them.
pub const KEY_WRAP_ROWS: TableName = TableName::new("key_wrap_rows");

const KEY_WRAP_ROW_KEY_FIELDS: &[RowField] = &[
    RowField::bytes32("workspace_id"),
    RowField::bytes32("frontier_id"),
    RowField::bytes32("recipient_key_id"),
    RowField::u8("wrapped_secret_kind"),
    RowField::u64be("range_start"),
    RowField::u64be("range_width"),
    RowField::bytes("bit_depth", 2),
    RowField::bytes32("fact_id_prefix"),
];
const KEY_WRAP_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::u8("version"),
    RowField::bytes32("key_wrap_id"),
    RowField::bytes32("signer_public_key"),
    RowField::bytes("wrap", encode::KEY_WRAP_BYTES),
];

pub const KEY_WRAP_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    KEY_WRAP_ROWS,
    KEY_WRAP_ROW_KEY_FIELDS,
    KEY_WRAP_ROW_VALUE_FIELDS,
);

pub fn key_wrap_row(input: queries::KeyWrapRow) -> Result<TableRow, String> {
    let wrap = &input.wrap;
    // Validates the wrap and produces canonical fact bytes for the row value.
    let wrap_bytes = encode::encode_key_wrap(wrap)?;
    KEY_WRAP_ROW_SCHEMA.row(
        &[
            RowValue::Bytes(wrap.workspace_id.to_vec()),
            RowValue::Bytes(wrap.frontier_id.to_vec()),
            RowValue::Bytes(wrap.recipient_key_id.to_vec()),
            RowValue::U8(wrap.wrapped_secret_kind.as_u8()),
            RowValue::U64(wrap.range_start),
            RowValue::U64(wrap.range_width),
            RowValue::Bytes(wrap.bit_depth.to_be_bytes().to_vec()),
            RowValue::Bytes(wrap.fact_id_prefix.to_vec()),
        ],
        &[
            RowValue::U8(1),
            RowValue::Bytes(input.key_wrap_id.to_vec()),
            RowValue::Bytes(input.signer_public_key.to_vec()),
            RowValue::Bytes(wrap_bytes),
        ],
    )
}
