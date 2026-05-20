//! Deferred protocol intents grouped by protocol theme.
//!
//! Each leaf module owns one durable verb: its payload layout, idempotence key,
//! exact fact inputs, and handler.

pub mod connection;
pub mod content;
pub mod encryption;
pub mod payload;
pub mod sync;
pub mod transport;
