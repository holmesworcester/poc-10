//! Shared user identity event.
//!
//! A user event publishes a user's signing key and display name. It must be
//! signed by the user-invite event that authorized that user to join.

pub mod cli;
pub mod codec;
pub mod commands;
pub mod projector;
pub mod schema;
pub mod types;

#[cfg(test)]
mod cli_tests;
