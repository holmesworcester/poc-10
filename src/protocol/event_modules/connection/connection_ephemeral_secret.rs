//! Local-only ephemeral key material for one connection handshake.
//!
//! The public half is copied into a connection request or connection event. The
//! private half stays local and is a normal durable dependency until TTL purge
//! removes it after the handshake/connection lifetime.

pub mod commands;
pub mod layout;
pub mod types;
