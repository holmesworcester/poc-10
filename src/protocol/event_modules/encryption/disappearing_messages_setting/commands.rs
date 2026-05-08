//! Commands for emitting `disappearing_messages_setting` events.
//!
//! The setting is signed by the authority admin (`authority_admin_event_id`)
//! and wrapped in this module's own signed envelope. The projector validates
//! that the envelope's signer matches the inner authority admin and that
//! the admin's public key matches the envelope's signer key.

use crate::core::crypto::Ed25519PrivateKey;
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::{CommandOutput, ProposedEvent};

use super::codec;
use super::types::DisappearingMessagesSettingEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetDisappearingMessages {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub ttl_minutes: u32,
    pub authority_admin_event_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetDisappearingMessagesOutput {
    pub setting_event_id: EventId,
    pub inner_setting_id: EventId,
}

pub fn set(
    input: SetDisappearingMessages,
) -> Result<CommandOutput<SetDisappearingMessagesOutput>, String> {
    let inner = DisappearingMessagesSettingEvent {
        created_at_ms: input.created_at_ms,
        workspace_id: input.workspace_id,
        ttl_minutes: input.ttl_minutes,
        authority_admin_event_id: input.authority_admin_event_id,
        effective_at_minute: input.created_at_ms / 60_000,
    };
    let payload = codec::encode(&inner);
    let inner_setting_id = event_id(&payload);
    let envelope = codec::sign(
        input.authority_admin_event_id,
        &input.signer_private_key,
        payload,
    );
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    let setting_event_id = event_id(&record.canonical_bytes);
    let proposed = ProposedEvent::new(record);
    Ok(CommandOutput::with_proposed_events(
        SetDisappearingMessagesOutput {
            setting_event_id,
            inner_setting_id,
        },
        vec![proposed],
    ))
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    #[test]
    fn set_proposes_signed_setting_event_with_admin_dep() {
        let signer_private_key = [9; crypto::ED25519_PRIVATE_KEY_BYTES];
        let output = set(SetDisappearingMessages {
            workspace_id: [1; 32],
            created_at_ms: 6_000_000,
            ttl_minutes: 5,
            authority_admin_event_id: [2; 32],
            signer_private_key,
        })
        .expect("set");
        assert_eq!(output.events.len(), 1);
        let record = output.events[0].record();
        assert_eq!(record.timestamp, 6_000_000);
        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.dependencies, vec![[2; 32], [1; 32]]);
    }

    #[test]
    fn deterministic_event_id_from_canonical_bytes() {
        let signer_private_key = [9; crypto::ED25519_PRIVATE_KEY_BYTES];
        let input = SetDisappearingMessages {
            workspace_id: [1; 32],
            created_at_ms: 6_000_000,
            ttl_minutes: 5,
            authority_admin_event_id: [2; 32],
            signer_private_key,
        };
        let first = set(input.clone()).expect("first");
        let second = set(input).expect("second");
        assert_eq!(first.events[0].event_id(), second.events[0].event_id());
    }
}

