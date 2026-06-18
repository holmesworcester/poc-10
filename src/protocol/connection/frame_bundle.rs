//! Bundled connection-frame wire fact family.
//!
//! A `connection_frame_bundle` fact is the runtime-local projection input for one
//! bundled encrypted connection frame. Receive projection pairs it with incoming
//! origin metadata and local `connection` context before opening the frame and
//! emitting durable child facts plus receipts.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
