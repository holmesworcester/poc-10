//! SQL-backed runtime pipeline.
//!
//! Core's runtime is a set of SQLite-backed queues. This facade keeps the
//! stable `core::pipeline` surface while the implementation is split by queue
//! responsibility:
//!
//! - `admission`: submit and purge facts, plus externally projected context.
//! - `fact_context`: wake due facts and run the fact/context fixed-point loop.
//! - `context_wake`: context delta matching that wakes newly satisfiable facts.
//! - `projection`: claim one pending fact and commit projection effects.
//! - `dispatch`: claim one intent and commit handler intent output.
//! - `effects`: shared pipeline side effects and commit helpers.

mod admission;
mod context_codec;
mod context_matching;
mod context_queue;
mod context_rows;
mod context_wake;
mod context_wake_sql;
mod dispatch;
mod effects;
mod fact_context;
mod intent_queue;
mod projection;
mod projection_commit;
mod projection_queue;
mod projection_run;
#[cfg(test)]
mod projection_run_tests;
mod report;

pub(crate) use crate::core::pipeline_storage::{persisted_fact, persisted_facts};
pub(crate) use crate::core::schema::{
    CONTEXT_NEEDS, CONTEXT_OFFERS, FACTS, INTENTS, LOCAL_INTENTS, PENDING_CONTEXT_CHANGES,
    PENDING_PROJECTION, PENDING_TIME_RANGES, TIME_WAKES,
};
pub(crate) use admission::{
    commit_projected_context_offers, purge_fact_from_store, submit_fact_to_store,
    submit_facts_to_store,
};
pub(crate) use context_codec::scope_key;
#[cfg(test)]
pub(crate) use context_codec::{context_need_row, context_offer_row};
pub(crate) use context_rows::persisted_context;
pub use dispatch::DispatchReport;
pub(crate) use dispatch::{
    dispatch_durable_intents, dispatch_local_intents, submit_intent_to_store,
    submit_local_intent_to_store,
};
pub use effects::PipelineEffects;
pub(crate) use effects::{
    commit_pipeline_effects_in_tx, commit_pipeline_effects_to_store, PipelineEffectCounts,
};
pub(crate) use fact_context::{process_due_time_range, process_pending_facts_and_context_changes};
pub use report::PipelineReport;
