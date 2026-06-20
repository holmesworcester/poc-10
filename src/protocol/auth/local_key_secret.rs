//! Local key secret fact family.
//!
//! A local key secret is private store material for a removal frontier's root
//! key. Projection ties it to its frontier and publishes wrap-source and
//! secret-coverage offers.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod proofs;

use crate::core::db::TableName;

pub const TYPE_LOCAL_KEY_SECRET: u8 = encode::TYPE_LOCAL_KEY_SECRET;

pub const LOCAL_KEY_SECRET_ROWS: TableName = TableName::new("local_key_secret_rows");

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalKeySecretFact, String> {
    project::decode::decode_local_key_secret(bytes)
}
