//! Projection for removal-frontier (wrap-source) facts.

use super::context as wrap_source_context;
use super::layout;
use crate::core::facts::Fact;
use crate::core::projection::ProjectionOutput;
use crate::event_modules::encryption::project::require_fact_scope;
use crate::event_modules::sealed_message;

pub fn project_removal_frontier(fact: &Fact) -> Result<ProjectionOutput, String> {
    let frontier = layout::decode_removal_frontier(&fact.bytes)?;
    let scope = sealed_message::context::workspace_scope(frontier.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new().offer(wrap_source_context::frontier_offer(
        fact.id, scope, fact.id,
    )))
}
