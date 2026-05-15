//! Reaction event leaf.
//!
//! This leaf owns signed, encrypted emoji reactions to workspace messages. It
//! relies on the message leaf for target existence, identity leaves for signer
//! authority, and encryption leaves for local content-key material. It does not
//! own display aggregation policy outside its row/query helpers, and it does
//! not perform retention cleanup for deleted target messages.

pub mod command_line;
pub mod commands;
pub mod layout;
pub mod projector;
pub mod queries;
pub mod rows;
pub mod types;
