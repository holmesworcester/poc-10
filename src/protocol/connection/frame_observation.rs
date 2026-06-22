//! Received wire-fact observation fact family.
//!
//! A `connection_frame_observation` fact is durable local metadata saying this
//! daemon observed a request, connection, or established frame wrapper fact from
//! a socket origin at a local time. Wire facts contain only received bytes; this
//! family supplies replay-safe receive context when a projector must park before
//! it can emit the final receive receipt.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
#[cfg(not(verus_keep_ghost))]
pub mod proofs;
