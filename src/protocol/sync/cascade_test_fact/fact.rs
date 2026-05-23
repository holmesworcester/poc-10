//! In-memory shape for synthetic cascade dependency facts.
//!
//! Cascade facts are not product protocol records. They are fixed-width test
//! facts that name up to `MAX_DEPS` predecessor fact ids and carry a stable
//! payload so the sync pipeline can be exercised with deterministic dependency
//! graphs. Change this file when the harness needs a different graph shape;
//! change projection or commands when the replay behavior changes.

use crate::core::facts::FactId;

pub const MAX_DEPS: usize = 10;
pub const PAYLOAD_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadeFact {
    pub timestamp: u64,
    pub dependencies: Vec<FactId>,
    pub payload: [u8; PAYLOAD_BYTES],
}
