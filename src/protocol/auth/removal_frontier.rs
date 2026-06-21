//! Removal frontier fact family.
//!
//! A removal frontier names the live content-key frontier for a workspace and
//! endpoint. Projection validates owner authority and publishes frontier context
//! that local secrets, key requests, and key wraps depend on.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;

use crate::core::db::TableName;

pub const TYPE_REMOVAL_FRONTIER: u8 = encode::TYPE_REMOVAL_FRONTIER;

pub const REMOVAL_FRONTIER_ROWS: TableName = TableName::new("removal_frontier_rows");

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::RemovalFrontierFact, String> {
    project::decode::decode_removal_frontier(bytes)
}
