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
//! - Parent descriptor existence + slice budget cross-check — runs in the
//!   admit pipeline once the file-row projection ordering is wired in.
//! - Per-slice nonce derivation and AEAD opening — owned by the encryption
//!   module, surfaces alongside the per-file content key.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

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
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let slice = layout::decode_fact(&fact.bytes)?;
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(content_file_slice_row(fact.id, &slice)?).into_intent()))
    }
}
