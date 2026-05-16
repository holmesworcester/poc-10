//! Concrete protocol fact modules grouped by protocol theme.
//!
//! Each leaf module owns one fact family, including layout, projector,
//! command helpers, row helpers, and protocol-specific validation.

pub mod connection;
pub mod content;
pub mod encryption;
pub mod identity;
pub mod sync;
pub mod transport;
