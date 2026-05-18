//! Poc-10 sealed-message projector.
//!
//! POLICY. A sealed-message-family fact is admitted iff:
//!   1. DISPATCH. The first byte selects a known sealed message helper type or
//!      signed sealed-message envelope.
//!   2. AUTHORITY. Message projection validates workspace, signer, author,
//!      secret coverage, and deletion context in submodules.
//!   3. MATERIALIZE. Helpers publish context offers; messages write/open rows
//!      through atomic intents and share facts with the workspace.

mod message;
mod offers;
mod validation;

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::protocol::facts::identity;

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
        // 1. Dispatch.
        match fact.bytes.first().copied() {
            Some(layout::TYPE_SEALED_MESSAGE) => message::project_message(fact, context),
            Some(identity::signed_fact::TYPE_SIGNED_FACT) => {
                message::project_signed_message(fact, context)
            }
            Some(layout::TYPE_SIGNER_PUBKEY) => offers::project_signer_pubkey(fact),
            Some(layout::TYPE_SECRET_NODE) => offers::project_secret_node(fact),
            Some(layout::TYPE_MESSAGE_DELETION) => offers::project_message_deletion(fact),
            _ => Err("unknown sealed-message fact type".to_string()),
        }
    }
}
