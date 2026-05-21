//! Protocol-neutral substrate.
//!
//! Core is the part of the program a different protocol should be able to
//! reuse unchanged. It supplies a small row store, opaque byte queues for raw
//! network traffic, and a TCP pump that moves length-prefixed frames. It must
//! not learn the vocabulary or validity rules of whatever protocol sits above
//! it.

pub mod app;
pub mod cli;
pub mod clock;
pub mod command_context;
pub mod context;
pub mod crypto;
pub mod daemon;
pub mod effects;
pub(crate) mod fact_store;
pub mod facts;
pub mod intents;
pub mod matchers;
pub mod network;
pub mod payload;
pub mod pipeline;
pub mod projectors;
pub mod runtime;
pub mod schema;
pub mod schema_dsl;
pub mod select;
pub(crate) mod sqlite_names;
pub mod store;
pub mod tcp;
pub mod wire;
