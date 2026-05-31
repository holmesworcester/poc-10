//! Learned peer-address surface.
//!
//! This is connection-maintenance-owned derived state, not a fact family: it
//! records the last reachable listen address learned for a peer endpoint so a
//! membership connection can find a known peer after an invite link expires.
//! The handshake request projector writes these rows (it carries each side's
//! listen address); `queries` reads them. There is no fact and no projector
//! here.

pub mod queries;
pub mod rows;
