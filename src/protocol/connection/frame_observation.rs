//! Received connection-frame observation fact family.
//!
//! A `connection_frame_observation` fact is durable local metadata saying this
//! daemon observed a canonical frame fact from a socket origin at a local time.
//! Frame facts contain only wire bytes; this family supplies the receive
//! context needed before those bytes may be opened.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
