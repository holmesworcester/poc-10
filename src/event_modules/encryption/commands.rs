//! User-facing encryption command constructors.

use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::event_modules::{identity_endpoint, identity_endpoint_shared, signed_fact};

use super::fact::{
    LocalKeySecretFact, LocalRecipientKeyFact, RecipientKeyFact, RemovalFrontierFact,
};
use super::{layout, matchers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateRecipientKey {
    pub created_at_ms: u64,
    pub workspace_id: FactId,
    pub previous_recipient_key_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateRecipientKeyReceipt {
    pub local_recipient_key_id: FactId,
    pub recipient_key_id: FactId,
    pub recipient_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateKeyFrontier {
    pub created_at_ms: u64,
    pub workspace_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateKeyFrontierReceipt {
    pub workspace_id: FactId,
    pub removal_frontier_id: FactId,
    pub local_key_secret_id: FactId,
    pub local_signer_secret_id: FactId,
}

pub fn create_recipient_key(
    ctx: &CommandContext<'_>,
    input: CreateRecipientKey,
) -> Result<CommandOutput<CreateRecipientKeyReceipt>, String> {
    let membership =
        identity_endpoint_shared::queries::local_membership(ctx.store(), input.workspace_id)?
            .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    if membership.endpoint_role != identity_endpoint_shared::fact::EndpointRole::Device {
        return Err("local endpoint role cannot receive key wraps".to_string());
    }
    let recipient_secret = crypto::random_x25519_private_key();
    let recipient_key = crypto::x25519_public_key(&recipient_secret);
    let recipient = RecipientKeyFact {
        workspace_id: input.workspace_id,
        endpoint_id: membership.endpoint_id,
        recipient_key,
        previous_recipient_key_id: input.previous_recipient_key_id,
        created_at_ms: input.created_at_ms,
    };
    let recipient_fact = Fact::new(
        matchers::workspace_scope(input.workspace_id),
        input.created_at_ms,
        layout::encode_recipient_key(&recipient)?,
    );
    let local = LocalRecipientKeyFact {
        workspace_id: input.workspace_id,
        recipient_key_id: recipient_fact.id,
        recipient_key,
        recipient_secret,
    };
    let local_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms,
        layout::encode_local_recipient_key(&local)?,
    );
    Ok(CommandOutput::new(CreateRecipientKeyReceipt {
        local_recipient_key_id: local_fact.id,
        recipient_key_id: recipient_fact.id,
        recipient_key,
    })
    .with_facts(vec![recipient_fact, local_fact]))
}

pub fn create_key_frontier(
    ctx: &CommandContext<'_>,
    input: CreateKeyFrontier,
) -> Result<CommandOutput<CreateKeyFrontierReceipt>, String> {
    let endpoint = identity_endpoint::queries::local_endpoint(ctx.store())?
        .ok_or_else(|| "local endpoint is not initialized".to_string())?;
    let membership =
        identity_endpoint_shared::queries::local_membership(ctx.store(), input.workspace_id)?
            .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    if membership.endpoint_id != endpoint.endpoint {
        return Err("local endpoint membership does not match local endpoint".to_string());
    }
    let frontier = RemovalFrontierFact {
        workspace_id: input.workspace_id,
        owner_endpoint_id: endpoint.endpoint,
        created_at_ms: input.created_at_ms,
    };
    let frontier_fact = Fact::new(
        matchers::workspace_scope(input.workspace_id),
        input.created_at_ms,
        layout::encode_removal_frontier(&frontier)?,
    );
    let local_secret = LocalKeySecretFact {
        workspace_id: input.workspace_id,
        frontier_id: frontier_fact.id,
        owner_endpoint_id: endpoint.endpoint,
        created_at_ms: input.created_at_ms,
        key_secret: crypto::random_xchacha20poly1305_key(),
    };
    let local_secret_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms,
        layout::encode_local_key_secret(&local_secret)?,
    );
    let signer = signed_fact::fact::LocalSignerSecretFact {
        workspace_id: input.workspace_id,
        signer_id: endpoint.endpoint,
        public_key: endpoint.signing_public_key,
        private_key: endpoint.signing_secret,
    };
    let signer_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms,
        signed_fact::layout::encode_local_signer_secret(&signer)?,
    );
    Ok(CommandOutput::new(CreateKeyFrontierReceipt {
        workspace_id: input.workspace_id,
        removal_frontier_id: frontier_fact.id,
        local_key_secret_id: local_secret_fact.id,
        local_signer_secret_id: signer_fact.id,
    })
    .with_facts(vec![frontier_fact, local_secret_fact, signer_fact]))
}
