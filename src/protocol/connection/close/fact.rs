//! Connection close fact payload.
//!
//! The payload names the local connection response fact that should be retired
//! and records the local close time. Close facts are local events: they do not
//! travel over connection frames and they do not contain private material.
//!
//! Keep this file to the typed payload shape. Byte compatibility belongs in
//! `layout.rs`, and cleanup policy belongs in the target projectors.

use crate::core::facts::FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionCloseFact {
    pub connection_id: FactId,
    pub closed_at_ms: u64,
}
