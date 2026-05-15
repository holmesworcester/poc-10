//! Commands for creating signed user invites.
//!
//! Commands return the signed event to admit and the invite id that later user
//! events must name as their signer dependency.

use crate::core::crypto::{self, Ed25519PrivateKey, Ed25519PublicKey};
use crate::protocol::event_modules::identity::signed;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::{layout, types::UserInviteEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateUserInvite {
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
    pub signer_event_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateUserInviteOutput {
    pub user_invite_id: EventId,
    pub public_key: Ed25519PublicKey,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
}

pub fn create(input: CreateUserInvite) -> Result<CommandOutput<CreateUserInviteOutput>, String> {
    let event = UserInviteEvent {
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
    let user_invite_id = signed.events[0].event_id();
    Ok(CommandOutput::with_proposed_events(
        CreateUserInviteOutput {
            user_invite_id,
            public_key: event.public_key,
            workspace_id: event.workspace_id,
            authority_event_id: event.authority_event_id,
        },
        signed.events,
    ))
}

/// Inputs the CLI uses when creating a workspace user invite alongside a
/// freshly-generated invite keypair. Mirrors `CreateUserInvite` without
/// the `public_key` field — `create_with_random_key` derives the
/// keypair internally and returns the private half so the CLI can pass
/// it to a follow-up `user::commands::create` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateUserInviteRandom {
    pub created_at_ms: u64,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
    pub signer_event_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
}

/// Output extension of `create_with_random_key`: same payload as
/// `CreateUserInviteOutput` plus the generated invite private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateUserInviteRandomOutput {
    pub user_invite_id: EventId,
    pub invite_private_key: Ed25519PrivateKey,
    pub public_key: Ed25519PublicKey,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
}

/// Generate a fresh invite keypair and produce the signed
/// `user_invite` event. Returns the private half so the caller can sign
/// the corresponding `user` event without round-tripping through the
/// CLI's crypto module.
pub fn create_with_random_key(
    input: CreateUserInviteRandom,
) -> Result<CommandOutput<CreateUserInviteRandomOutput>, String> {
    let invite_private_key = crypto::random_ed25519_private_key();
    let public_key = crypto::ed25519_public_key(&invite_private_key);
    let inner = create(CreateUserInvite {
        created_at_ms: input.created_at_ms,
        public_key,
        workspace_id: input.workspace_id,
        authority_event_id: input.authority_event_id,
        signer_event_id: input.signer_event_id,
        signer_private_key: input.signer_private_key,
    })?;
    Ok(CommandOutput::with_proposed_events(
        CreateUserInviteRandomOutput {
            user_invite_id: inner.value.user_invite_id,
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
    use crate::protocol::event_modules::identity::signed;
    use crate::protocol::event_modules::types::event_id;

    use super::*;

    #[test]
    fn create_returns_signed_user_invite_with_signer_dependency() {
        let workspace_id = [2; 32];
        let signer_private_key = [7; 32];
        let invite_public_key = crypto::ed25519_public_key(&[8; 32]);
        let output = create(CreateUserInvite {
            created_at_ms: 11,
            public_key: invite_public_key,
            workspace_id,
            authority_event_id: workspace_id,
            signer_event_id: workspace_id,
            signer_private_key,
        })
        .expect("create user_invite");

        assert_eq!(output.events.len(), 1);
        let proposed = &output.events[0];
        assert_eq!(output.value.user_invite_id, proposed.event_id());
        assert_eq!(
            proposed.event_id(),
            event_id(&proposed.record().canonical_bytes)
        );
        assert_eq!(proposed.record().dependencies, vec![workspace_id]);

        let envelope = signed::layout::decode(&proposed.record().canonical_bytes)
            .expect("decode signed envelope");
        assert_eq!(envelope.signer_event_id, workspace_id);
        assert_eq!(envelope.inner_type, layout::TYPE_USER_INVITE);

        let decoded = layout::decode(&envelope.payload).expect("decode user_invite payload");
        assert_eq!(decoded.created_at_ms, 11);
        assert_eq!(decoded.public_key, invite_public_key);
        assert_eq!(decoded.workspace_id, workspace_id);
        assert_eq!(decoded.authority_event_id, workspace_id);
    }
}
