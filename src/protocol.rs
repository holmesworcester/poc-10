//! Concrete protocol module map.
//!
//! This root is intentionally only a manifest. Declarative protocol metadata
//! lives in `protocol::registry`; the executable description consumed by core
//! lives in `protocol::app`.
//!
//! Protocol state is organized by scope, not by layer. Each scope module groups
//! everything for one protocol concern: its fact families, its deferred intent
//! handlers, and its CLI adapters. A reader can follow a concern from command
//! creation, through canonical encoding, projector-local decode/auth/adapt,
//! typed indexes, queries, and the intents that perform delayed work - all in
//! one place.
//!
//! Each scope module root is the navigational map for that scope. Fact families
//! are noun-named submodules (`message`, `key_wrap`); intents are verb-named
//! submodules (`close`, `queue_outgoing_frame`). The current fact-family shape is
//! `fact.rs` for typed payloads, `encode.rs` for canonical bytes, `project.rs`
//! for projector-local decode/auth/adapt plus semantic projection and effects,
//! `author.rs` for construction, and `queries.rs` for user-facing reads. Intents
//! own their payload layout, idempotence key, exact fact inputs, and handler.
//!
//! Scopes are: auth authority and key material, content and retention,
//! connection protocol, and sync convergence. Shared helpers stay inside the
//! scope that owns their protocol concern.

pub mod app;
pub(crate) mod cli;
pub mod registry;

pub mod auth;
pub mod connection;
pub mod content;
pub mod sync;
