//! Poc-10 encryption projector for key healing and wrap requests.

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::project_key_request::project_key_request;
use super::project_local_material::{project_local_history_node_secret, project_local_key_secret};
use super::project_local_recipient_key::project_local_recipient_key;
use super::project_recipient_key::project_recipient_key;
use super::project_removal_frontier::project_removal_frontier;
use super::project_signed_key_wrap::project_signed_key_wrap;
use crate::event_modules::signed_fact;

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
            Some(layout::TYPE_RECIPIENT_KEY) => project_recipient_key(fact, context),
            Some(layout::TYPE_REMOVAL_FRONTIER) => project_removal_frontier(fact),
            Some(layout::TYPE_LOCAL_KEY_SECRET) => project_local_key_secret(fact, context),
            Some(layout::TYPE_LOCAL_HISTORY_NODE_SECRET) => {
                project_local_history_node_secret(fact, context)
            }
            Some(layout::TYPE_LOCAL_RECIPIENT_KEY) => project_local_recipient_key(fact, context),
            Some(layout::TYPE_KEY_REQUEST) => project_key_request(fact, context),
            Some(signed_fact::layout::TYPE_SIGNED_FACT) => project_signed_key_wrap(fact, context),
            _ => Err("unknown encryption fact type".to_string()),
        }
    }
}
