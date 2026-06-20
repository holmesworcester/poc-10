//! Small connection-frame wire fact family.
//!
//! A `connection_frame_small` fact is the runtime-local projection input for one
//! small encrypted connection frame. Receive projection pairs it with incoming
//! origin metadata and local `connection` context before opening the frame and
//! emitting contained facts as incoming projection inputs plus durable receipts.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod proofs;
