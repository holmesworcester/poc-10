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
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use super::ProjectionPayload;

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
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for SealedMessageProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        payload: ProjectionPayload,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Dispatch.
        match payload {
            ProjectionPayload::Message(payload) => message::project_message(fact, context, payload),
            ProjectionPayload::SignedMessage(signed) => {
                message::project_signed_message(fact, context, signed)
            }
            ProjectionPayload::SignerPubkey(signer) => offers::project_signer_pubkey(fact, signer),
            ProjectionPayload::SecretNode(node) => offers::project_secret_node(fact, node),
            ProjectionPayload::MessageDeletion(deletion) => {
                offers::project_message_deletion(fact, deletion)
            }
        }
    }
}
