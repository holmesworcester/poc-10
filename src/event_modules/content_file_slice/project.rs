//! Poc-10 content-file-slice projector.
//!
//! Decodes a content-file-slice fact and emits a single `PutRow` into
//! `file_slice_rows`. The slice event id used in the row value is the fact id;
//! the key is workspace/file/slice-index so range scans return slices in order.
//!
//! Parity gaps (intentional, deferred to later slices):
//! - Signed-envelope verification (separate event module).
//! - BAO proof verification against the parent descriptor's root hash —
//!   depends on the file-send command wave reintroducing the proof slot.
//! - Parent descriptor existence and slice-index bounds are validated from
//!   matched file context; broader slice-budget enforcement remains in the
//!   file-send command wave.
//! - Per-slice nonce derivation and AEAD opening — owned by the encryption
//!   module, surfaces alongside the per-file content key.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::content_file::{layout as file_layout, matchers as file_matchers};
use crate::event_modules::content_message::matchers as message_matchers;

use super::layout;
use super::rows::content_file_slice_row;

#[derive(Debug, Clone, Default)]
pub struct ContentFileSliceProjector;

impl ContentFileSliceProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentFileSliceProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let slice = layout::decode_fact(&fact.bytes)?;
        let scope = message_matchers::workspace_scope(slice.workspace_id);
        require_fact_scope(fact, &scope)?;
        let file_need = file_matchers::file_need(fact.id, scope, slice.file_id);
        let Some(parent) = context.payload_for(&file_need) else {
            return Ok(ProjectionOutput::new().need(file_need));
        };
        let file = file_layout::decode_fact(&parent.bytes)
            .map_err(|_| "file slice parent context is not a content file".to_string())?;
        if file.workspace_id != slice.workspace_id {
            return Err("file slice parent workspace does not match slice".to_string());
        }
        if file.file_id != slice.file_id {
            return Err("file slice parent file_id does not match slice".to_string());
        }
        if slice.slice_index >= file.total_slices {
            return Err("file slice index is out of range for parent file".to_string());
        }
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(content_file_slice_row(fact.id, &slice)?).into_intent()))
    }
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content file slice fact scope does not match body workspace".to_string())
    }
}
