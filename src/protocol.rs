//! Concrete protocol module map.
//!
//! This root is intentionally only a manifest. Declarative protocol metadata
//! lives in `protocol::catalog`; the executable description consumed by core
//! lives in `protocol::registry`.

pub mod catalog;
pub(crate) mod command_handlers;
pub mod commands;
pub mod facts;
pub mod intents;
pub mod matchers;
pub mod registry;
pub mod runtime;
