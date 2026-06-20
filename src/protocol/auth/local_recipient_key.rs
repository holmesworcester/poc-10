//! Local recipient key fact family.
//!
//! A local recipient key holds private material that lets this store unwrap key
//! wraps. Projection proves it matches the shared recipient fact and self-purges
//! when the recipient key is superseded.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod proofs;

use crate::core::db::TableName;

pub const TYPE_LOCAL_RECIPIENT_KEY: u8 = encode::TYPE_LOCAL_RECIPIENT_KEY;

pub const LOCAL_RECIPIENT_KEY_ROWS: TableName = TableName::new("local_recipient_key_rows");

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalRecipientKeyFact, String> {
    project::decode::decode_local_recipient_key(bytes)
}
