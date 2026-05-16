//! Poc-10 sealed-message projector.

mod message;
mod offers;
mod validation;

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::protocol::fact_modules::signed_fact;

use super::layout;

#[derive(Debug, Clone, Default)]
pub struct SealedMessageProjector;

impl SealedMessageProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SealedMessageProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(layout::TYPE_SEALED_MESSAGE) => message::project_message(fact, context),
            Some(signed_fact::layout::TYPE_SIGNED_FACT) => {
                message::project_signed_message(fact, context)
            }
            Some(layout::TYPE_SIGNER_PUBKEY) => offers::project_signer_pubkey(fact),
            Some(layout::TYPE_SECRET_NODE) => offers::project_secret_node(fact),
            Some(layout::TYPE_MESSAGE_DELETION) => offers::project_message_deletion(fact),
            _ => Err("unknown sealed-message fact type".to_string()),
        }
    }
}
