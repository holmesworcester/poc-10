//! Poc-10 sync context projector.
//!
//! Sync facts project availability and demand; they do not own socket IO or
//! mutate the sync index. A range request becomes either context needs or a
//! bounded send intent once the encrypted root, its dependency, and its key
//! wrap are all visible in the same workspace. The projector therefore remains
//! a deterministic bridge between context matching and handler work.

mod offers;
mod range_request;
mod validation;

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;

#[derive(Debug, Clone, Default)]
pub struct SyncContextProjector;

impl SyncContextProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncContextProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(layout::TYPE_SYNC_RANGE_REQUEST) => {
                range_request::project_sync_range_request(fact, projection_context)
            }
            Some(layout::TYPE_ENCRYPTED_ROOT) => offers::project_encrypted_root(fact),
            Some(layout::TYPE_SHARED_EVENT) => offers::project_shared_event(fact),
            Some(layout::TYPE_KEY_WRAP_AVAILABLE) => offers::project_key_wrap_available(fact),
            _ => Err("unknown sync context fact type".to_string()),
        }
    }
}
