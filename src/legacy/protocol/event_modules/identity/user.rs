//! Shared user identity event.
//!
//! A user event publishes a user's signing key and display name. It must be
//! signed by the user-invite event that authorized that user to join.

pub mod command_line;
pub mod commands;
pub mod layout;
pub mod projector;
pub mod rows;
pub mod types;

#[cfg(test)]
mod cli_tests;
