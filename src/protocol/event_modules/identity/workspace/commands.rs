//! Commands for workspace events.
//!
//! Creating a workspace emits two canonical events in dependency order:
//!   1. The workspace event itself (the shared root fact for identity).
//!   2. An initial `disappearing_messages_setting` event carrying the
//!      requested workspace-wide TTL. The setting depends on the
//!      workspace event, so the pipeline admits them in order.
//!
//! `disappearing_messages_setting` is the sole source of truth for the
//! workspace TTL/floor; the workspace event itself carries no TTL field.
//!
//! The initial setting uses the workspace event id as its
//! `authority_admin_event_id` and is signed by the workspace's private
//! key. The setting projector special-cases this bootstrap path so the
//! first setting can exist before the admin chain is built up.

use crate::core::crypto::Ed25519PrivateKey;
use crate::protocol::event_modules::encryption::disappearing_messages_setting;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{CommandOutput, ProposedEvent};

use super::codec;
use super::types::{WorkspaceEvent, WorkspacePublicKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorkspace {
    pub created_at_ms: u64,
    pub public_key: WorkspacePublicKey,
    /// Workspace root private key used to sign the initial
    /// `disappearing_messages_setting` event. Must be the secret half
    /// of `public_key`; the setting projector validates the envelope
    /// signature against the workspace event's public key.
    pub signer_private_key: Ed25519PrivateKey,
    /// Initial workspace-wide disappearing-messages TTL. Stamped into
    /// the initial `disappearing_messages_setting` event emitted
    /// alongside the workspace event; `0` disables disappearing
    /// messages at creation time.
    pub disappearing_ttl_minutes: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorkspaceOutput {
    pub workspace_id: EventId,
    pub initial_setting_event_id: EventId,
}

pub fn create(input: CreateWorkspace) -> Result<CommandOutput<CreateWorkspaceOutput>, String> {
    let event = WorkspaceEvent {
        created_at_ms: input.created_at_ms,
        public_key: input.public_key,
        name: input.name,
    };
    let bytes = codec::encode(&event)?;
    let record = codec::record_from_bytes(bytes)?;
    let workspace_proposed = ProposedEvent::new(record);
    let workspace_id = workspace_proposed.event_id();

    let initial_setting = disappearing_messages_setting::commands::set(
        disappearing_messages_setting::commands::SetDisappearingMessages {
            workspace_id,
            created_at_ms: input.created_at_ms,
            ttl_minutes: input.disappearing_ttl_minutes,
            // The workspace event itself acts as the bootstrap authority.
            // The setting projector accepts this special-case wiring as
            // long as `previous_setting_id` is `None`.
            authority_admin_event_id: workspace_id,
            signer_private_key: input.signer_private_key,
            expires_at_or_before_minute: 0,
            previous_setting_id: None,
        },
    )?;
    let initial_setting_event_id = initial_setting
        .events
        .first()
        .ok_or_else(|| "initial setting command produced no event".to_string())?
        .event_id();

    let mut events = Vec::with_capacity(1 + initial_setting.events.len());
    events.push(workspace_proposed);
    events.extend(initial_setting.events.into_iter());

    Ok(CommandOutput::with_proposed_events(
        CreateWorkspaceOutput {
            workspace_id,
            initial_setting_event_id,
        },
        events,
    ))
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::protocol::event_modules::types::event_id;

    use super::*;

    fn workspace_keypair() -> ([u8; 32], [u8; 32]) {
        let private_key = [9; crypto::ED25519_PRIVATE_KEY_BYTES];
        let public_key = crypto::ed25519_public_key(&private_key);
        (private_key, public_key)
    }

    #[test]
    fn create_returns_consistent_event_id_and_record() {
        let (private_key, public_key) = workspace_keypair();
        let output = create(CreateWorkspace {
            created_at_ms: 77,
            public_key,
            signer_private_key: private_key,
            disappearing_ttl_minutes: 0,
            name: "Design".to_string(),
        })
        .expect("create workspace");

        // Two events: the workspace itself and the initial setting.
        assert_eq!(output.events.len(), 2);
        let workspace_proposed = &output.events[0];
        let initial_setting_proposed = &output.events[1];
        assert_eq!(output.value.workspace_id, workspace_proposed.event_id());
        assert_eq!(
            output.value.initial_setting_event_id,
            initial_setting_proposed.event_id()
        );
        assert_eq!(
            workspace_proposed.event_id(),
            event_id(&workspace_proposed.record().canonical_bytes)
        );

        let decoded = codec::decode(&workspace_proposed.record().canonical_bytes)
            .expect("decode proposed workspace");
        assert_eq!(decoded.created_at_ms, 77);
        assert_eq!(decoded.public_key, public_key);
        assert_eq!(decoded.name, "Design");
    }

    #[test]
    fn create_rejects_non_canonical_workspace_name() {
        let (private_key, public_key) = workspace_keypair();
        let err = create(CreateWorkspace {
            created_at_ms: 77,
            public_key,
            signer_private_key: private_key,
            disappearing_ttl_minutes: 0,
            name: "bad\0name".to_string(),
        })
        .expect_err("reject NUL name");
        assert!(err.contains("NUL"));
    }

    #[test]
    fn initial_setting_carries_requested_ttl_and_no_previous_setting() {
        let (private_key, public_key) = workspace_keypair();
        let output = create(CreateWorkspace {
            created_at_ms: 6_000_000,
            public_key,
            signer_private_key: private_key,
            disappearing_ttl_minutes: 5,
            name: "Ops".to_string(),
        })
        .expect("create workspace");

        // The initial setting is the second emitted event.
        let setting_record = output.events[1].record();
        let envelope = disappearing_messages_setting::codec::decode_signed(
            &setting_record.canonical_bytes,
        )
        .expect("decode signed setting");
        let setting = disappearing_messages_setting::codec::decode(&envelope.payload)
            .expect("decode setting");
        assert_eq!(setting.ttl_minutes, 5);
        assert_eq!(setting.workspace_id, output.value.workspace_id);
        assert_eq!(setting.expires_at_or_before_minute, 0);
        assert!(setting.previous_setting_id.is_none());
        assert_eq!(setting.authority_admin_event_id, output.value.workspace_id);
    }
}
