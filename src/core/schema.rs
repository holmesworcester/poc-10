//! Core-owned schema declarations.
//!
//! Durable runtime tables and restart-local memory tables are declared in
//! `schema.p8sql`.

use crate::core::store::TableName;

pub const CORE_SCHEMA_SOURCE: &str = include_str!("schema.p8sql");

pub(crate) const FACTS: TableName = TableName::new("facts");
pub(crate) const CONTEXT_NEEDS: TableName = TableName::new("context_needs");
pub(crate) const CONTEXT_OFFERS: TableName = TableName::new("context_offers");
pub(crate) const TIME_WAKES: TableName = TableName::new("time_wakes");
pub(crate) const PENDING_PROJECTION: TableName = TableName::new("pending_projection");
pub(crate) const PENDING_TIME_RANGES: TableName = TableName::new("pending_time_ranges");
pub(crate) const PENDING_CONTEXT_CHANGES: TableName = TableName::new("pending_context_changes");
pub(crate) const INTENTS: TableName = TableName::new("intents");
pub(crate) const LOCAL_INTENTS: TableName = TableName::new("local_intents");
