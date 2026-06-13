//! Small connection-frame wire fact family.
//!
//! A `connection_frame_small` fact is the runtime-local projection input for one
//! small encrypted connection frame. Receive projection pairs it with local
//! `connection_frame_observation` context before opening the frame and emitting
//! durable child facts plus receipts.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
