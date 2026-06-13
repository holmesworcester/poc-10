//! File-slice connection-frame wire fact family.
//!
//! A `connection_frame_file_slice` fact is local ephemeral input for one
//! encrypted connection frame sized for a content file slice. Receive
//! projection pairs it with local `connection_frame_observation` context before
//! opening the frame and emitting durable child facts plus receipts.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
