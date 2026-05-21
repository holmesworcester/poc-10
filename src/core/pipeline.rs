//! SQL-backed runtime pipeline.
//!
//! Core's runtime is a set of SQLite-backed queues. This facade keeps the
//! stable `core::pipeline` surface while the implementation is split by queue
//! responsibility:
//!
//! - `admission`: submit and purge facts, plus externally projected context.
//! - `time_wake`: convert due time ranges into pending projections.
//! - `context_wake`: context delta matching that wakes newly satisfiable facts.
//! - `projection`: claim one pending fact and commit projection effects.
//! - `dispatch`: claim one intent and commit handler intent output.
//! - `queues`: small shared queue helpers.

mod admission;
mod context_wake;
mod dispatch;
mod driver;
mod projection;
mod queues;
mod report;
mod tables;
mod time_wake;

pub(crate) use crate::core::pipeline_storage::{
    persisted_context, persisted_fact, persisted_facts,
};
pub(crate) use admission::{
    commit_projected_context_offers, purge_fact_from_store, submit_fact_to_store,
    submit_facts_to_store,
};
pub use dispatch::DispatchReport;
pub(crate) use dispatch::{
    dispatch_durable_intents, dispatch_local_intents, submit_intent_to_store,
    submit_local_intent_to_store,
};
pub(crate) use driver::process_pending_facts_and_context_changes;
pub use report::PipelineReport;
pub(crate) use tables::{
    CONTEXT_NEEDS, CONTEXT_OFFERS, FACTS, INTENTS, LOCAL_INTENTS, PENDING_CONTEXT_CHANGES,
    PENDING_PROJECTION, PENDING_TIME_RANGES, SCHEMAS, TIME_WAKES,
};
pub(crate) use time_wake::process_due_time_range;
