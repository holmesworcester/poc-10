//! Poc-10 encryption projector for key healing and wrap requests.

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::key_request::key_request;
use super::layout;
use super::local_material::{project_local_history_node_secret, project_local_key_secret};
use super::local_recipient_key::local_recipient_key;
use super::recipient_key::recipient_key;
use super::signed_key_wrap::signed_key_wrap;
use super::validation::require_fact_scope;
use crate::protocol::facts::identity;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers;

#[derive(Debug, Clone, Default)]
pub struct EncryptionProjector;

impl EncryptionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for EncryptionProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(layout::TYPE_RECIPIENT_KEY) => recipient_key(fact, context),
            Some(layout::TYPE_REMOVAL_FRONTIER) => removal_frontier(fact),
            Some(layout::TYPE_LOCAL_KEY_SECRET) => project_local_key_secret(fact, context),
            Some(layout::TYPE_LOCAL_HISTORY_NODE_SECRET) => {
                project_local_history_node_secret(fact, context)
            }
            Some(layout::TYPE_LOCAL_RECIPIENT_KEY) => local_recipient_key(fact, context),
            Some(layout::TYPE_KEY_REQUEST) => key_request(fact, context),
            Some(identity::signed_fact::layout::TYPE_SIGNED_FACT) => signed_key_wrap(fact, context),
            _ => Err("unknown encryption fact type".to_string()),
        }
    }
}

fn removal_frontier(fact: &Fact) -> Result<ProjectionOutput, String> {
    let frontier = layout::decode_removal_frontier(fact.body())?;
    let scope = matchers::workspace_scope(frontier.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new()
        .offer(matchers::frontier_offer(fact.id, scope, fact.id))
        .intent(share_fact_with_workspace_intent_for_fact(
            frontier.workspace_id,
            fact,
        )))
}
