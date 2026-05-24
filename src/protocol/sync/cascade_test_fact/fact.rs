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
pub struct CascadeDependencies {
    count: u8,
    ids: [FactId; MAX_DEPS],
}

impl CascadeDependencies {
    pub fn new(ids: &[FactId]) -> Result<Self, String> {
        if ids.len() > MAX_DEPS {
            return Err("cascade fact dependency count exceeds fixed fields".to_string());
        }
        let mut slots = [[0; 32]; MAX_DEPS];
        for (index, id) in ids.iter().copied().enumerate() {
            slots[index] = id;
        }
        Ok(Self {
            count: ids.len() as u8,
            ids: slots,
        })
    }

    pub fn len(&self) -> usize {
        self.count as usize
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = FactId> + '_ {
        self.ids[..self.len()].iter().copied()
    }

    pub(crate) fn padded_ids(&self) -> &[FactId; MAX_DEPS] {
        &self.ids
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadeTestFact {
    pub timestamp: u64,
    pub dependencies: CascadeDependencies,
    pub payload: [u8; PAYLOAD_BYTES],
}
