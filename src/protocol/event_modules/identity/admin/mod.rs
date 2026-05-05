//! Admin identity grants.
//!
//! Admin events bind a workspace-scoped user identity to the public key that is
//! allowed to act as an administrator. The workspace-root bootstrap grant is
//! direct; ongoing grants are signed by the authority admin key.

pub mod codec;
pub mod commands;
pub mod projector;
pub mod schema;
pub mod types;

#[cfg(test)]
mod cli_tests;
