//! Projector for signed recipient key events.
//!
//! Projection validates that the signing endpoint membership belongs to the
//! same workspace and owns the signing public key named by the envelope. It
//! writes the public recipient-key row only; local private material and wrap
//! scheduling belong to sibling local event leaves and workers.
//!
//! Supersession: when the canonical event carries a non-zero
//! `previous_recipient_key_id`, the projector also exact-deletes the old
//! `RECIPIENT_KEYS` row in the same projection. The single event then acts
//! as both the tombstone of the old pubkey and the introduction of the new
//! one (per `RULES.md` § "Forward Secrecy Requires Recipient Key Rotation
//! On Wrap-Bound Deletion"). Validation requires the predecessor to be
//! issued by the same endpoint and live in the same workspace; cross-
//! endpoint or cross-workspace supersessions are rejected.

use crate::protocol::event_modules::identity::{endpoint_shared, signed};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput, TableDelete};

use super::types::NO_PREVIOUS_RECIPIENT_KEY;
use super::{codec, commands, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let recipient_key = codec::decode(&envelope.payload)?;
    commands::validate_event_ids(&recipient_key)?;
    if event.record.workspace_id != Some(recipient_key.workspace_id) {
        return Err("recipient key workspace metadata does not match event body".to_string());
    }
    if envelope.signer_endpoint_shared_id != recipient_key.endpoint_shared_id {
        return Err("recipient key signer does not match payload endpoint".to_string());
    }
    if recipient_key.previous_recipient_key_id == event.context.event_id {
        return Err(
            "recipient key cannot supersede itself (previous_recipient_key_id == event_id)"
                .to_string(),
        );
    }

    let signer = event
        .context
        .dependency(&envelope.signer_endpoint_shared_id)
        .ok_or_else(|| "recipient key signer endpoint_shared dependency is missing".to_string())?;
    let signer_envelope = signed::codec::decode(&signer.canonical_bytes).map_err(|_| {
        "recipient key signer dependency is not a signed endpoint_shared".to_string()
    })?;
    if signer_envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err("recipient key signer dependency is not a signed endpoint_shared".to_string());
    }
    let signer_endpoint_shared =
        endpoint_shared::codec::decode(&signer_envelope.payload).map_err(|_| {
            "recipient key signer dependency is not a signed endpoint_shared".to_string()
        })?;
    if signer_endpoint_shared.workspace_id != recipient_key.workspace_id {
        return Err(
            "recipient key signer endpoint_shared workspace does not match event".to_string(),
        );
    }
    if signer_endpoint_shared.signing_public_key != envelope.signer_public_key {
        return Err("recipient key signer public key does not match endpoint_shared".to_string());
    }
    if !signer_endpoint_shared.endpoint_role.can_receive_key_wraps() {
        return Err("recipient key signer endpoint role cannot receive key wraps".to_string());
    }

    let mut output = ProjectionOutput::rows(vec![schema::recipient_key_row(
        event.context.event_id,
        &recipient_key,
    )?]);

    if recipient_key.previous_recipient_key_id != NO_PREVIOUS_RECIPIENT_KEY {
        validate_predecessor(event, &recipient_key.previous_recipient_key_id, recipient_key.endpoint_shared_id, recipient_key.workspace_id)?;
        output.deletes.push(TableDelete {
            table: schema::RECIPIENT_KEYS,
            key: schema::recipient_key_key(
                recipient_key.workspace_id,
                recipient_key.previous_recipient_key_id,
            ),
        });
    }

    Ok(output)
}

/// The predecessor recipient_key event must live in the same workspace and
/// be signed by the same endpoint membership as this replacement. Without
/// these checks an attacker could publish a `recipient_key` claiming to
/// supersede an unrelated peer's pubkey and trick projection into deleting
/// it.
fn validate_predecessor(
    event: &EventWithContext<'_>,
    previous_recipient_key_id: &EventId,
    expected_endpoint_shared_id: EventId,
    expected_workspace_id: EventId,
) -> Result<(), String> {
    let predecessor = event
        .context
        .dependency(previous_recipient_key_id)
        .ok_or_else(|| {
            "recipient key supersession previous_recipient_key dependency is missing".to_string()
        })?;
    let predecessor_envelope =
        codec::decode_signed(&predecessor.canonical_bytes).map_err(|_| {
            "recipient key supersession previous dependency is not a signed recipient_key"
                .to_string()
        })?;
    let predecessor_event = codec::decode(&predecessor_envelope.payload).map_err(|_| {
        "recipient key supersession previous dependency is not a signed recipient_key"
            .to_string()
    })?;
    if predecessor_event.workspace_id != expected_workspace_id {
        return Err(
            "recipient key supersession previous_recipient_key workspace does not match"
                .to_string(),
        );
    }
    if predecessor_event.endpoint_shared_id != expected_endpoint_shared_id {
        return Err(
            "recipient key supersession previous_recipient_key endpoint does not match \
             (cross-endpoint supersession is rejected)"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::{endpoint_shared, signed};
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::commands;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn signing_public_key_for(private_key: &[u8; 32]) -> [u8; 32] {
        codec::sign([0; 32], private_key, vec![codec::TYPE_RECIPIENT_KEY]).signer_public_key
    }

    fn endpoint_shared_record(workspace_id: [u8; 32], signing_public_key: [u8; 32]) -> Record {
        endpoint_shared_record_with_role(
            workspace_id,
            signing_public_key,
            crate::protocol::event_modules::identity::endpoint::types::EndpointRole::Device,
        )
    }

    fn endpoint_shared_record_with_role(
        workspace_id: [u8; 32],
        signing_public_key: [u8; 32],
        endpoint_role: crate::protocol::event_modules::identity::endpoint::types::EndpointRole,
    ) -> Record {
        let payload =
            endpoint_shared::codec::encode(&endpoint_shared::types::EndpointSharedEvent {
                created_at_ms: 4,
                workspace_id,
                user_authority_event_id: [3; 32],
                endpoint_id: [21; 32],
                signing_public_key,
                endpoint_role,
                device_name: "laptop".to_string(),
            })
            .expect("encode endpoint_shared");
        let signed = signed::commands::sign_payload([6; 32], &[5; 32], payload)
            .expect("sign endpoint_shared");
        signed.events[0].record().clone()
    }

    fn event_with_context<'a>(
        record: &'a Record,
        signer_id: [u8; 32],
        signer_record: Record,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies: vec![DependencyContext {
                    event_id: signer_id,
                    record: signer_record,
                }],
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        }
    }

    fn recipient_key_record(
        workspace_id: [u8; 32],
        signer_id: [u8; 32],
        signer_private_key: [u8; 32],
    ) -> Record {
        let local = super::super::super::local_recipient_key::commands::create(workspace_id)
            .expect("create local key")
            .value;
        commands::publish(commands::PublishRecipientKey {
            workspace_id,
            created_at_ms: 10,
            endpoint_shared_id: signer_id,
            signer_private_key,
            recipient_key: local.recipient_key,
            previous_recipient_key_id: NO_PREVIOUS_RECIPIENT_KEY,
        })
        .expect("publish")
        .events[0]
            .record()
            .clone()
    }

    #[test]
    fn projects_recipient_key_row_from_authorized_endpoint() {
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let signer_record = endpoint_shared_record([1; 32], signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let event = event_with_context(&record, signer_id, signer_record);

        let output = project(&event).expect("project recipient key");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::RECIPIENT_KEYS);
        let row = schema::decode_recipient_key_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, [1; 32]);
        assert_eq!(row.recipient_key_id, event.context.event_id);
        assert_eq!(row.endpoint_shared_id, signer_id);
    }

    #[test]
    fn rejects_missing_signer_dependency() {
        let signer_private_key = [9; 32];
        let signer_record =
            endpoint_shared_record([1; 32], signing_public_key_for(&signer_private_key));
        let signer_id = event_id(&signer_record.canonical_bytes);
        let record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies: Vec::new(),
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        };

        assert_eq!(
            project(&event).expect_err("missing signer must fail"),
            "recipient key signer endpoint_shared dependency is missing"
        );
    }

    #[test]
    fn rejects_signer_public_key_or_workspace_mismatch() {
        let signer_private_key = [9; 32];
        let signer_record = endpoint_shared_record([1; 32], signing_public_key_for(&[8; 32]));
        let signer_id = event_id(&signer_record.canonical_bytes);
        let record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let event = event_with_context(&record, signer_id, signer_record);
        assert_eq!(
            project(&event).expect_err("wrong key must fail"),
            "recipient key signer public key does not match endpoint_shared"
        );

        let signer_record =
            endpoint_shared_record([2; 32], signing_public_key_for(&signer_private_key));
        let signer_id = event_id(&signer_record.canonical_bytes);
        let record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let event = event_with_context(&record, signer_id, signer_record);
        assert_eq!(
            project(&event).expect_err("wrong workspace must fail"),
            "recipient key signer endpoint_shared workspace does not match event"
        );
    }

    #[test]
    fn supersession_event_emits_table_delete_for_previous_key_row() {
        // The forward-secrecy rotation path uses a new `recipient_key`
        // event whose `previous_recipient_key_id` names a wiped pubkey.
        // The projector must emit a TableDelete for the predecessor's
        // RECIPIENT_KEYS row so the workspace's active recipient set
        // flips over in the same projection.
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let signer_record = endpoint_shared_record([1; 32], signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);

        let predecessor_record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let predecessor_id = event_id(&predecessor_record.canonical_bytes);

        // Author the replacement that supersedes the predecessor.
        let local = super::super::super::local_recipient_key::commands::create([1; 32])
            .expect("create local key")
            .value;
        let replacement_record = commands::publish(commands::PublishRecipientKey {
            workspace_id: [1; 32],
            created_at_ms: 12,
            endpoint_shared_id: signer_id,
            signer_private_key,
            recipient_key: local.recipient_key,
            previous_recipient_key_id: predecessor_id,
        })
        .expect("publish supersession")
        .events[0]
            .record()
            .clone();

        let event = EventWithContext {
            record: &replacement_record,
            context: EventContext {
                event_id: event_id(&replacement_record.canonical_bytes),
                dependencies: vec![
                    DependencyContext {
                        event_id: signer_id,
                        record: signer_record,
                    },
                    DependencyContext {
                        event_id: predecessor_id,
                        record: predecessor_record,
                    },
                ],
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        };

        let output = project(&event).expect("project supersession");

        assert_eq!(output.rows.len(), 1, "must write one new row");
        assert_eq!(
            output.deletes.len(),
            1,
            "supersession must emit one TableDelete for the predecessor row"
        );
        assert_eq!(output.deletes[0].table, schema::RECIPIENT_KEYS);
        assert_eq!(
            output.deletes[0].key,
            schema::recipient_key_key([1; 32], predecessor_id),
            "the deleted row key must be the predecessor's"
        );
    }

    #[test]
    fn supersession_event_rejects_predecessor_from_different_endpoint() {
        // An attacker authoring a recipient_key that claims to supersede
        // a victim's pubkey must be rejected: the predecessor's
        // endpoint_shared_id must match the new event's signer.
        let signer_private_key = [9; 32];
        let signer_record = endpoint_shared_record(
            [1; 32],
            signing_public_key_for(&signer_private_key),
        );
        let signer_id = event_id(&signer_record.canonical_bytes);
        let other_private_key = [7; 32];
        let other_record = endpoint_shared_record(
            [1; 32],
            signing_public_key_for(&other_private_key),
        );
        let other_id = event_id(&other_record.canonical_bytes);

        // Predecessor authored by `other`.
        let other_predecessor =
            recipient_key_record([1; 32], other_id, other_private_key);
        let other_predecessor_id = event_id(&other_predecessor.canonical_bytes);

        // Attacker (signer) tries to supersede `other`'s pubkey.
        let local = super::super::super::local_recipient_key::commands::create([1; 32])
            .expect("create local key")
            .value;
        let attacker_record = commands::publish(commands::PublishRecipientKey {
            workspace_id: [1; 32],
            created_at_ms: 12,
            endpoint_shared_id: signer_id,
            signer_private_key,
            recipient_key: local.recipient_key,
            previous_recipient_key_id: other_predecessor_id,
        })
        .expect("publish")
        .events[0]
            .record()
            .clone();

        let event = EventWithContext {
            record: &attacker_record,
            context: EventContext {
                event_id: event_id(&attacker_record.canonical_bytes),
                dependencies: vec![
                    DependencyContext {
                        event_id: signer_id,
                        record: signer_record,
                    },
                    DependencyContext {
                        event_id: other_predecessor_id,
                        record: other_predecessor,
                    },
                ],
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        };

        let err = project(&event).expect_err("cross-endpoint supersession must fail");
        assert!(
            err.contains("cross-endpoint supersession is rejected"),
            "expected cross-endpoint rejection, got: {err}"
        );
    }

    #[test]
    fn rejects_invite_server_endpoint_recipient_key() {
        let signer_private_key = [9; 32];
        let signer_record = endpoint_shared_record_with_role(
            [1; 32],
            signing_public_key_for(&signer_private_key),
            crate::protocol::event_modules::identity::endpoint::types::EndpointRole::InviteServer,
        );
        let signer_id = event_id(&signer_record.canonical_bytes);
        let record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let event = event_with_context(&record, signer_id, signer_record);

        assert_eq!(
            project(&event).expect_err("invite-server recipient key must fail"),
            "recipient key signer endpoint role cannot receive key wraps"
        );
    }
}
