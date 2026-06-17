//! Recipient key fact family.
//!
//! A recipient key names an endpoint public key eligible to receive workspace
//! auth key material. Projection validates supersession and emits proactive
//! key-wrap work.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;

use crate::core::db::TableName;

pub const TYPE_RECIPIENT_KEY: u8 = encode::TYPE_RECIPIENT_KEY;

pub const RECIPIENT_KEY_ROWS: TableName = TableName::new("recipient_key_rows");

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::RecipientKeyFact, String> {
    project::decode::decode_recipient_key(bytes)
}
