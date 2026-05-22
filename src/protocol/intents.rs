//! Deferred protocol intents grouped by protocol theme.
//!
//! Intent modules are the protocol's asynchronous verbs. Projection and
//! commands emit these verbs when work should happen later through the core
//! intent queue instead of inside the current projector or command. Handlers
//! then load their declared fact inputs, query protocol rows if needed, and
//! return `PipelineEffects` for core to commit.
//!
//! Each leaf module owns one durable or ephemeral verb family: payload layout,
//! idempotence key, exact fact inputs, handler retry policy, and tests. The
//! module that emits an intent should use the constructor from the owning leaf
//! module rather than assembling kind/key/payload bytes itself.
//!
//! Use these modules for work with side effects or delayed dependencies:
//! sending network frames, sharing facts, responding to sync compares,
//! unwrapping key material, or purging derived state. User-facing workflows
//! belong in fact command modules; deterministic row derivation belongs in
//! projectors.

pub mod connection;
pub mod content;
pub mod encryption;
pub mod payload;
pub mod sync;
pub mod transport;
