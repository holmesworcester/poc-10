//! Commands for creating device-invite events.
//!
//! The shared event carries only the invite public key plus the workspace/user
//! authority it binds. The private key is returned to the caller as invite
//! material so a later endpoint-shared command can produce a real signed
//! envelope.

use rand_core::{OsRng, RngCore};

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{CommandOutput, ProposedEvent};

use super::codec;
use super::types::{DeviceInviteEvent, DeviceInviteKeypair};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateDeviceInvite {
    pub created_at_ms: u64,
    pub workspace_id: EventId,
    pub user_authority_event_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateDeviceInviteOutput {
    pub device_invite_id: EventId,
    pub keypair: DeviceInviteKeypair,
}

pub fn create(
    input: CreateDeviceInvite,
) -> Result<CommandOutput<CreateDeviceInviteOutput>, String> {
    create_with_private_key(input, random_private_key())
}

pub fn create_with_private_key(
    input: CreateDeviceInvite,
    private_key: Ed25519PrivateKey,
) -> Result<CommandOutput<CreateDeviceInviteOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("user_authority_event_id", &input.user_authority_event_id)?;

    let public_key = crypto::ed25519_public_key(&private_key);
    let event = DeviceInviteEvent {
        created_at_ms: input.created_at_ms,
        workspace_id: input.workspace_id,
        user_authority_event_id: input.user_authority_event_id,
        public_key,
    };
    let bytes = codec::encode(&event);
    let proposed = ProposedEvent::new(codec::record_from_bytes(bytes)?);
    let device_invite_id = proposed.event_id();

    Ok(CommandOutput::with_proposed_events(
        CreateDeviceInviteOutput {
            device_invite_id,
            keypair: DeviceInviteKeypair {
                public_key,
                private_key,
            },
        },
        vec![proposed],
    ))
}

fn random_private_key() -> Ed25519PrivateKey {
    let mut private_key = [0; crypto::ED25519_PRIVATE_KEY_BYTES];
    OsRng.fill_bytes(&mut private_key);
    private_key
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::{event_id, EventScope};

    use super::*;

    fn input() -> CreateDeviceInvite {
        CreateDeviceInvite {
            created_at_ms: 55,
            workspace_id: [1; 32],
            user_authority_event_id: [2; 32],
        }
    }

    #[test]
    fn create_returns_invite_keypair_and_shared_event() {
        let private_key = [7; crypto::ED25519_PRIVATE_KEY_BYTES];
        let output = create_with_private_key(input(), private_key).expect("create device invite");

        assert_eq!(output.events.len(), 1);
        assert_eq!(
            output.value.keypair.public_key,
            crypto::ed25519_public_key(&private_key)
        );
        assert_eq!(output.value.keypair.private_key, private_key);

        let proposed = &output.events[0];
        assert_eq!(output.value.device_invite_id, proposed.event_id());
        assert_eq!(
            proposed.event_id(),
            event_id(&proposed.record().canonical_bytes)
        );
        assert_eq!(proposed.record().scope, EventScope::Shared);
        assert_eq!(proposed.record().dependencies, vec![[1; 32], [2; 32]]);

        let decoded =
            codec::decode(&proposed.record().canonical_bytes).expect("decode device invite");
        assert_eq!(decoded.created_at_ms, 55);
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.user_authority_event_id, [2; 32]);
        assert_eq!(decoded.public_key, output.value.keypair.public_key);
    }

    #[test]
    fn create_rejects_empty_workspace_or_user_authority() {
        let private_key = [7; crypto::ED25519_PRIVATE_KEY_BYTES];

        let err = create_with_private_key(
            CreateDeviceInvite {
                workspace_id: [0; 32],
                ..input()
            },
            private_key,
        )
        .expect_err("empty workspace must fail");
        assert_eq!(err, "workspace_id cannot be empty");

        let err = create_with_private_key(
            CreateDeviceInvite {
                user_authority_event_id: [0; 32],
                ..input()
            },
            private_key,
        )
        .expect_err("empty authority must fail");
        assert_eq!(err, "user_authority_event_id cannot be empty");
    }
}
