//! Concrete protocol module map.
//!
//! This root is intentionally only a manifest. Declarative protocol metadata
//! lives in `protocol::registry`; the executable description consumed by core
//! lives in `protocol::app`.
//!
//! Protocol state is organized by scope, not by layer. Each scope module groups
//! everything for one protocol concern: its fact families, its deferred intent
//! handlers, and its CLI adapters. A reader can follow a concern from command
//! creation, through fact layout and projection, into derived rows, queries,
//! and the intents that perform delayed work - all in one place.
//!
//! Each scope module root is the navigational map for that scope. Fact families
//! are noun-named submodules (`message`, `key_wrap`); intents are verb-named
//! submodules (`close`, `send_network_frame`). The usual fact
//! shape is `fact.rs` for typed payloads, `layout.rs` for stable bytes,
//! `project.rs` for admission and derived state, `rows.rs` for projected SQL
//! rows, `queries.rs` for user-facing reads, and `commands.rs`/`create.rs` for
//! constructors. Intents own their payload layout, idempotence key, exact fact
//! inputs, and handler.
//!
//! Scopes are: auth authority and key material, content and retention,
//! connection protocol, and sync convergence. `payload` holds intent payload
//! machinery shared across scope intent modules.

pub mod app;
pub(crate) mod cli;
pub mod payload;
pub mod registry;

pub mod auth;
pub mod connection;
pub mod content;
pub mod sync;
