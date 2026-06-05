//! Concrete protocol module map.
//!
//! This root is intentionally only a manifest. Declarative protocol metadata
//! lives in `protocol::registry`; the executable description consumed by core
//! lives in `protocol::app`.
//!
//! Protocol state is organized by scope, not by layer. Each scope module groups
//! everything for one protocol concern: its fact families, its deferred intent
//! handlers, and its CLI adapters. A reader can follow a concern from command
//! creation, through canonical encode/decode, authentication, adaptation,
//! projection, typed indexes, queries, and the intents that perform delayed
//! work - all in one place.
//!
//! Each scope module root is the navigational map for that scope. Fact families
//! are noun-named submodules (`message`, `key_wrap`); intents are verb-named
//! submodules (`close`, `send_network_frame`). The current fact-family shape is
//! `fact.rs` for typed payloads, `encode.rs` for canonical bytes, `decode.rs`
//! for strict byte parsing, `authenticate.rs` for fact-boundary proof,
//! `adapt.rs` for projection input shaping, `project.rs` for semantic
//! projection and effects, `author.rs` for construction, and `queries.rs` for
//! user-facing reads. Intents own their payload layout, idempotence key, exact
//! fact inputs, and handler.
//!
//! Scopes are: auth authority and key material, content and retention,
//! connection protocol, and sync convergence. `payload` holds intent payload
//! machinery shared across scope intent modules. `connection_frame*` holds the
//! established-connection encrypted byte machinery shared by connection frame
//! fact families and send/receive intents; it is not itself a fact family.

pub mod app;
pub(crate) mod cli;
pub mod connection_frame;
pub mod connection_frame_wire;
pub mod payload;
pub mod registry;

pub mod auth;
pub mod connection;
pub mod content;
pub mod sync;
