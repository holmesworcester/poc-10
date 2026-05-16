use crate::core::facts::Fact;
use crate::core::projection::ProjectionOutput;
use crate::event_modules::encryption::{layout, matchers};
use crate::event_modules::sealed_message;

use super::validation::require_fact_scope;

pub(super) fn removal_frontier(fact: &Fact) -> Result<ProjectionOutput, String> {
    let frontier = layout::decode_removal_frontier(&fact.bytes)?;
    let scope = sealed_message::matchers::workspace_scope(frontier.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new().offer(matchers::frontier_offer(fact.id, scope, fact.id)))
}
