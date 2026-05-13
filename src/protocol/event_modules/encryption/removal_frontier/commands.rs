//! Commands for removal frontier events.
//!
//! The wire type carries a fixed number of sorted refs. Commands therefore own
//! fan-in: ordinary frontiers produce one event, and unusual concurrent removal
//! bursts produce a small tree of frontier events whose root is the returned
//! `removal_frontier_id`. This keeps the protocol event shape fixed while still
//! allowing the dependency closure to cover every referenced removal boundary.

use crate::core::crypto::Ed25519PrivateKey;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{CommandOutput, ProposedEvent};

use super::codec;
use super::types::{RemovalFrontierEvent, MAX_REMOVAL_FRONTIER_REFS};

/// Sanity guard: non-zero ids and sorted/unique refs. The codec is
/// intentionally lenient on decode; this helper is shared between the
/// authoring path and the receive projector so a malformed peer event is
/// rejected at projection time too.
pub(super) fn validate_event_fields(event: &RemovalFrontierEvent) -> Result<(), String> {
    if is_zero(&event.workspace_id) {
        return Err("removal frontier workspace cannot be empty".to_string());
    }
    if is_zero(&event.authority_admin_id) {
        return Err("removal frontier authority_admin_id cannot be empty".to_string());
    }
    if event.removal_event_ids.len() > MAX_REMOVAL_FRONTIER_REFS {
        return Err("removal frontier has too many refs".to_string());
    }
    for id in &event.removal_event_ids {
        if is_zero(id) {
            return Err("removal frontier ref cannot be empty".to_string());
        }
    }
    let mut sorted = event.removal_event_ids.clone();
    sorted.sort();
    sorted.dedup();
    if sorted != event.removal_event_ids {
        return Err("removal frontier refs must be sorted and unique".to_string());
    }
    Ok(())
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRemovalFrontier {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub authority_admin_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub removal_event_ids: Vec<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRemovalFrontierOutput {
    pub removal_frontier_id: EventId,
    pub workspace_id: EventId,
    pub authority_admin_id: EventId,
    pub removal_event_ids: Vec<EventId>,
}

pub fn create(
    input: CreateRemovalFrontier,
) -> Result<CommandOutput<CreateRemovalFrontierOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("authority_admin_id", &input.authority_admin_id)?;
    validate_id(
        "signer_endpoint_shared_id",
        &input.signer_endpoint_shared_id,
    )?;
    validate_refs(&input.removal_event_ids)?;

    let removal_event_ids = input.removal_event_ids.clone();
    let mut events = Vec::new();
    let removal_frontier_id = build_frontier_tree(&input, removal_event_ids.clone(), &mut events)?;

    let value = CreateRemovalFrontierOutput {
        removal_frontier_id,
        workspace_id: input.workspace_id,
        authority_admin_id: input.authority_admin_id,
        removal_event_ids,
    };
    Ok(CommandOutput::with_proposed_events(value, events))
}

fn build_frontier_tree(
    input: &CreateRemovalFrontier,
    refs: Vec<EventId>,
    events: &mut Vec<ProposedEvent>,
) -> Result<EventId, String> {
    if refs.len() <= MAX_REMOVAL_FRONTIER_REFS {
        let event = proposed_frontier_event(input, refs)?;
        let event_id = event.event_id();
        events.push(event);
        return Ok(event_id);
    }

    let mut child_ids = Vec::new();
    for chunk in refs.chunks(MAX_REMOVAL_FRONTIER_REFS) {
        let event = proposed_frontier_event(input, chunk.to_vec())?;
        child_ids.push(event.event_id());
        events.push(event);
    }
    child_ids.sort();
    if has_duplicate(&child_ids) {
        return Err("removal frontier fan-in produced duplicate child ids".to_string());
    }
    build_frontier_tree(input, child_ids, events)
}

fn proposed_frontier_event(
    input: &CreateRemovalFrontier,
    removal_event_ids: Vec<EventId>,
) -> Result<ProposedEvent, String> {
    let event = RemovalFrontierEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        authority_admin_id: input.authority_admin_id,
        removal_event_ids,
    };
    let payload = codec::encode(&event)?;
    let envelope = codec::sign(
        input.signer_endpoint_shared_id,
        &input.signer_private_key,
        payload,
    );
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    Ok(ProposedEvent::new(record))
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

fn validate_refs(refs: &[EventId]) -> Result<(), String> {
    for id in refs {
        validate_id("removal frontier ref", id)?;
    }
    let mut sorted = refs.to_vec();
    sorted.sort();
    if sorted != refs {
        return Err("removal frontier refs must be sorted and unique".to_string());
    }
    if has_duplicate(refs) {
        return Err("removal frontier refs must be sorted and unique".to_string());
    }
    Ok(())
}

fn has_duplicate(ids: &[EventId]) -> bool {
    ids.windows(2).any(|pair| pair[0] == pair[1])
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    fn ref_id(byte: u8) -> EventId {
        [byte; 32]
    }

    fn decode_frontier(event: &ProposedEvent) -> RemovalFrontierEvent {
        let envelope = codec::decode_signed(&event.record().canonical_bytes).expect("envelope");
        codec::decode(&envelope.payload).expect("frontier")
    }

    #[test]
    fn create_proposes_signed_shared_frontier() {
        let output = create(CreateRemovalFrontier {
            workspace_id: [1; 32],
            created_at_ms: 10,
            authority_admin_id: [2; 32],
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_event_ids: Vec::new(),
        })
        .expect("create");

        assert_eq!(output.events.len(), 1);
        let record = output.events[0].record();
        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.dependencies, vec![[3; 32], [1; 32], [2; 32]]);
        assert_eq!(
            output.value.removal_frontier_id,
            output.events[0].event_id()
        );
    }

    #[test]
    fn create_rejects_empty_workspace() {
        let err = create(CreateRemovalFrontier {
            workspace_id: [0; 32],
            created_at_ms: 10,
            authority_admin_id: [2; 32],
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_event_ids: Vec::new(),
        })
        .expect_err("empty workspace must fail");

        assert_eq!(err, "workspace_id cannot be empty");
    }

    #[test]
    fn create_caps_ref_fan_in_with_dependency_ordered_frontier_tree() {
        let refs = vec![ref_id(4), ref_id(5), ref_id(6), ref_id(7), ref_id(8)];
        let output = create(CreateRemovalFrontier {
            workspace_id: [1; 32],
            created_at_ms: 10,
            authority_admin_id: [2; 32],
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_event_ids: refs.clone(),
        })
        .expect("create");

        assert_eq!(output.events.len(), 3);
        assert_eq!(output.value.removal_event_ids, refs);
        assert_eq!(
            output.value.removal_frontier_id,
            output.events.last().expect("root event").event_id()
        );
        let first_child = decode_frontier(&output.events[0]);
        let second_child = decode_frontier(&output.events[1]);
        let root = decode_frontier(&output.events[2]);
        assert_eq!(
            first_child.removal_event_ids.len(),
            MAX_REMOVAL_FRONTIER_REFS
        );
        assert_eq!(second_child.removal_event_ids.len(), 1);
        let mut child_ids = vec![output.events[0].event_id(), output.events[1].event_id()];
        child_ids.sort();
        assert_eq!(root.removal_event_ids, child_ids);
        for event in &output.events {
            assert!(decode_frontier(event).removal_event_ids.len() <= MAX_REMOVAL_FRONTIER_REFS);
        }
    }

    #[test]
    fn create_builds_multiple_frontier_levels_for_large_bursts() {
        let refs = (10..27).map(ref_id).collect::<Vec<_>>();
        let output = create(CreateRemovalFrontier {
            workspace_id: [1; 32],
            created_at_ms: 10,
            authority_admin_id: [2; 32],
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_event_ids: refs.clone(),
        })
        .expect("create");

        assert_eq!(output.value.removal_event_ids, refs);
        assert_eq!(output.events.len(), 8);
        assert_eq!(
            output.value.removal_frontier_id,
            output.events.last().expect("root event").event_id()
        );
        for event in &output.events {
            assert!(decode_frontier(event).removal_event_ids.len() <= MAX_REMOVAL_FRONTIER_REFS);
        }
    }
}
