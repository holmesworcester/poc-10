//! Unified connection fact family.
//!
//! A connection completes a bootstrap or membership handshake. The same sealed
//! fact is sent by the responder and projected by both parties; its fact id is
//! the connection id and projection writes the live connection row used by frame
//! and sync routing.

pub mod authenticate;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;
