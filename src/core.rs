//! Protocol-neutral substrate.
//!
//! Core is the part of the program a different protocol should be able to
//! reuse unchanged. It supplies a small row store, opaque byte queues for raw
//! network traffic, and a TCP pump that moves length-prefixed frames. It must
//! not learn the vocabulary or validity rules of whatever protocol sits above
//! it.
//!
//! The central runtime loop is fact-based. Protocol code admits immutable facts
//! and idempotent intents; core stores them, runs projection, matches context,
//! dispatches handlers, and commits `PipelineEffects` through SQLite
//! transactions. Core owns the queue mechanics and atomicity rules. Protocol
//! modules own byte layouts, authority checks, user-facing commands, and the
//! meaning of projected rows.
//!
//! Start in `runtime` for the host-facing facade, `project_fact` for projection
//! contracts and one fact projection transaction, `handle_intent` for one intent
//! transaction, `schema` for core tables, and `store` for the SQLite substrate.
//! Use `app`, `daemon`, and `cli` when working on process or command hosting. If
//! a change requires knowing what a workspace, message, invite, key wrap, or sync
//! range means, it belongs under `protocol`, not here.

pub mod app;
pub mod cli;
pub mod clock;
pub mod command;
pub mod context;
pub mod crypto;
pub mod daemon;
pub mod effects;
pub mod facts;
pub(crate) mod handle_intent;
pub mod intents;
pub mod network;
pub mod perf_profile;
pub mod project_fact;
pub mod replay;
pub mod row_schema;
pub mod runtime;
pub mod schema;
pub mod store;
pub mod versioning;
pub mod wire;
