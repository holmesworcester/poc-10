//! Poc-10 content-file projector.
//!
//! Decodes a content-file fact and emits a single `PutRow` into `file_rows`.
//! The file event id used in the row key is the fact id.
//!
//! Parity gaps (intentional, deferred to later slices):
//! - Signed-envelope verification (separate event module).
//! - Author workspace-membership cross-check (depends on identity-membership
//!   projections that haven't landed in the target tree yet).
//! - Sibling message dependency / tombstone cascade (lives in the
//!   content-purge handler, depends on per-message tombstone rows).
//! - `blob_bytes <= MAX_FILE_BYTES` and `total_slices * slice_bytes >=
//!   blob_bytes` invariants — legacy ran these against pre-decryption sizes.
//!   The target slice-budget enforcement will move into the file-send command
//!   wave; this projector only owns the row layout.
//! - Per-file leaf-coord / frontier derivation — depends on per-message FS.
//! - Sealed-metadata AEAD opening — depends on encryption module surfacing the
//!   per-file content key.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::content_file_row;

#[derive(Debug, Clone, Default)]
pub struct ContentFileProjector;

impl ContentFileProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentFileProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let file = layout::decode_fact(&fact.bytes)?;
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(content_file_row(fact.id, &file)?).into_intent()))
    }
}
