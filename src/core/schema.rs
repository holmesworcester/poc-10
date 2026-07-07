//! Core-owned schema declarations.
//!
//! `schema.p8sql` is the durable and memory table inventory for the generic
//! runtime: facts, local admissions, standing context, time wakes, pending
//! projection, intent queues, and the store-local clock. This file only exposes
//! the source text and typed `TableName` constants so the rest of core does not
//! repeat string literals.
//!
//! Add a table here when the table is part of core's runtime mechanics. Add it
//! in a protocol module when it stores protocol meaning, even if core commits
//! the row mutation.

use crate::core::store::TableName;

/// The core p8sql schema source applied to every runtime store.
pub const CORE_SCHEMA_SOURCE: &str = include_str!("schema.p8sql");

/// Local admission metadata table for content-addressed fact bytes.
pub(crate) const LOCAL_FACT_ADMISSIONS: TableName = TableName::new("local_fact_admissions");
/// Standing context edge table.
pub(crate) const CONTEXT_EDGES: TableName = TableName::new("context_edges");
/// Standing time wake table.
pub(crate) const TIME_WAKES: TableName = TableName::new("time_wakes");
/// Pending projection queue table.
pub(crate) const PENDING_PROJECTION: TableName = TableName::new("pending_projection");
/// Transient due-time context table.
pub(crate) const PENDING_TIME_RANGES: TableName = TableName::new("pending_time_ranges");
/// Durable intent queue table.
pub(crate) const INTENTS: TableName = TableName::new("intents");
/// Restart-local intent queue table.
pub(crate) const LOCAL_INTENTS: TableName = TableName::new("local_intents");
