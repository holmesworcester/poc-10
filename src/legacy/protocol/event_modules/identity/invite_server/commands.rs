//! Commands for creating signed invite-server invites.
//!
//! The command signs one invite-server payload using an existing authority
//! event. It does not create local invite links, listen on sockets, or admit
//! endpoint_shared events; CLI/bootstrap code owns those workflow steps.

use crate::core::crypto::{self, Ed25519PrivateKey, Ed25519PublicKey};
use crate::legacy::protocol::event_modules::identity::signed;
use crate::legacy::protocol::event_modules::types::EventId;
use crate::legacy::protocol::event_modules::worker::CommandOutput;

use super::{layout, types::InviteServerEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateInviteServer {
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
    pub signer_event_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateInviteServerOutput {
    pub invite_server_id: EventId,
    pub public_key: Ed25519PublicKey,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
}

pub fn create(
    input: CreateInviteServer,
) -> Result<CommandOutput<CreateInviteServerOutput>, String> {
    let event = InviteServerEvent {
        created_at_ms: input.created_at_ms,
        public_key: input.public_key,
        workspace_id: input.workspace_id,
        authority_event_id: input.authority_event_id,
    };
    let signed = signed::commands::sign_payload(
        input.signer_event_id,
        &input.signer_private_key,
        layout::encode(&event),
    )?;
    let invite_server_id = signed.events[0].event_id();
    Ok(CommandOutput::with_proposed_events(
        CreateInviteServerOutput {
            invite_server_id,
            public_key: event.public_key,
            workspace_id: event.workspace_id,
            authority_event_id: event.authority_event_id,
        },
        signed.events,
    ))
}

/// Inputs for `create_with_random_key`: same as `CreateInviteServer`
/// without the `public_key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateInviteServerRandom {
    pub created_at_ms: u64,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
    pub signer_event_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
}

/// Output of `create_with_random_key`: same as `CreateInviteServerOutput`
/// plus the generated invite private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateInviteServerRandomOutput {
    pub invite_server_id: EventId,
    pub invite_private_key: Ed25519PrivateKey,
    pub public_key: Ed25519PublicKey,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
}

/// Generate a fresh invite keypair and produce the signed
/// `invite_server` event.
pub fn create_with_random_key(
    input: CreateInviteServerRandom,
) -> Result<CommandOutput<CreateInviteServerRandomOutput>, String> {
    let invite_private_key = crypto::random_ed25519_private_key();
    let public_key = crypto::ed25519_public_key(&invite_private_key);
    let inner = create(CreateInviteServer {
        created_at_ms: input.created_at_ms,
        public_key,
        workspace_id: input.workspace_id,
        authority_event_id: input.authority_event_id,
        signer_event_id: input.signer_event_id,
        signer_private_key: input.signer_private_key,
    })?;
    Ok(CommandOutput::with_proposed_events(
        CreateInviteServerRandomOutput {
            invite_server_id: inner.value.invite_server_id,
            invite_private_key,
            public_key: inner.value.public_key,
            workspace_id: inner.value.workspace_id,
            authority_event_id: inner.value.authority_event_id,
        },
        inner.events,
    ))
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::legacy::protocol::event_modules::identity::signed;
    use crate::legacy::protocol::event_modules::types::event_id;

    use super::*;

    #[test]
    fn create_returns_signed_invite_server_with_signer_dependency() {
        let workspace_id = [2; 32];
        let signer_private_key = [7; 32];
        let invite_public_key = crypto::ed25519_public_key(&[8; 32]);
        let output = create(CreateInviteServer {
            created_at_ms: 11,
            public_key: invite_public_key,
            workspace_id,
            authority_event_id: workspace_id,
            signer_event_id: workspace_id,
            signer_private_key,
        })
        .expect("create invite_server");

        assert_eq!(output.events.len(), 1);
        let proposed = &output.events[0];
        assert_eq!(output.value.invite_server_id, proposed.event_id());
        assert_eq!(
            proposed.event_id(),
            event_id(&proposed.record().canonical_bytes)
        );
        assert_eq!(proposed.record().dependencies, vec![workspace_id]);

        let envelope = signed::layout::decode(&proposed.record().canonical_bytes)
            .expect("decode signed envelope");
        assert_eq!(envelope.signer_event_id, workspace_id);
        assert_eq!(envelope.inner_type, layout::TYPE_INVITE_SERVER);

        let decoded = layout::decode(&envelope.payload).expect("decode invite_server payload");
        assert_eq!(decoded.created_at_ms, 11);
        assert_eq!(decoded.public_key, invite_public_key);
        assert_eq!(decoded.workspace_id, workspace_id);
        assert_eq!(decoded.authority_event_id, workspace_id);
    }
}
