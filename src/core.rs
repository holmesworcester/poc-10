//! Protocol-neutral substrate.
//!
//! Core is the part of the program a different protocol should be able to
//! reuse unchanged. It supplies a small row store, opaque byte queues for raw
//! network traffic, and a TCP pump that moves length-prefixed frames. It must
//! not learn the vocabulary or validity rules of whatever protocol sits above
//! it.

pub mod cli;
pub mod command_context;
pub mod context;
pub(crate) mod context_change_helpers;
pub mod context_change_pipeline;
pub mod crypto;
pub mod daemon;
pub mod facts;
pub mod intent_pipeline;
pub mod intents;
pub mod logical_clock;
pub mod matchers;
pub mod network;
pub mod network_queues;
pub(crate) mod pending_fact_pipeline;
pub mod projection;
pub mod runtime;
pub mod schema_dsl;
pub mod store;
pub mod tcp;
pub mod wire;
