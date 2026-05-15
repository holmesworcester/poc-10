//! Poc-10 workspace projector.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::core::store::{TableName, TableRow};

use super::layout;

pub const WORKSPACE_ROWS: TableName = TableName::new("workspace_rows");

#[derive(Debug, Clone, Default)]
pub struct WorkspaceProjector;

impl WorkspaceProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for WorkspaceProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let workspace = layout::decode_fact(&fact.bytes)?;
        Ok(ProjectionOutput::new().intent(
            AtomicIntent::PutRow(TableRow {
                table: WORKSPACE_ROWS,
                key: fact.id.to_vec(),
                value: layout::encode_row_value(&workspace)?,
            })
            .into_intent(),
        ))
    }
}
