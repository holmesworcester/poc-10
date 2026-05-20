//! Concrete protocol module map.
//!
//! This root is intentionally only a manifest. Declarative protocol metadata
//! lives in `protocol::registry`; the executable description consumed by core
//! lives in `protocol::app`.

pub mod app;
pub(crate) mod command_handlers;
pub mod facts;
pub mod intents;
pub mod matchers;
pub mod registry;
