//! Shared user-invite identity event.
//!
//! A user invite authorizes one future `user` event in a workspace. The shared
//! event is carried inside a signed envelope; the envelope signer is the
//! immediate dependency that projection validates against the workspace root.

pub mod codec;
pub mod commands;
pub mod projector;
pub mod schema;
pub mod types;
