//! Transit fact sendability helpers.
//!
//! Transit send handlers ask this module whether a fact may leave the local
//! store. The checks stay beside the transit protocol rules instead of in the
//! handler that performs the eventual network effect.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::event_modules::{
    connection_ephemeral_secret, connection_request, connection_response, encryption,
    identity_endpoint, identity_invite, local_history_node_secret, signed_fact, transit_received,
};

use super::frame::{self, SealConnectionFrame, TransitFactBundle};

/// Return the bytes that may be packaged into a transit frame.
///
/// Local facts and private/local fact tags are never transport payloads. A
/// signed envelope is decoded here as a defensive check that the envelope
/// itself is valid and does not hide a private local payload type.
pub fn require_sendable_fact(fact: &Fact) -> Result<&[u8], String> {
    if fact.scope == FactScope::Local {
        return Err(format!("transit send refused local fact {:?}", fact.id));
    }

    let tag = fact
        .bytes
        .first()
        .copied()
        .ok_or_else(|| format!("transit send refused empty fact {:?}", fact.id))?;
    if is_private_local_fact_tag(tag) {
        return Err(format!(
            "transit send refused private/local fact tag {tag} for {:?}",
            fact.id
        ));
    }

    if tag == signed_fact::layout::TYPE_SIGNED_FACT {
        let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes).map_err(|err| {
            format!(
                "transit send refused invalid signed fact {:?}: {err}",
                fact.id
            )
        })?;
        if is_private_local_fact_tag(envelope.inner_type) {
            return Err(format!(
                "transit send refused private/local signed payload tag {} for {:?}",
                envelope.inner_type, fact.id
            ));
        }
    }

    Ok(&fact.bytes)
}

pub fn is_private_local_fact_tag(tag: u8) -> bool {
    matches!(
        tag,
        connection_ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET
            | connection_request::layout::TYPE_CONNECTION_REQUEST
            | connection_response::layout::TYPE_CONNECTION_RESPONSE
            | identity_endpoint::layout::TYPE_LOCAL_ENDPOINT
            | identity_invite::layout::TYPE_INVITE_SECRET
            | local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET
            | signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET
            | encryption::layout::TYPE_LOCAL_KEY_SECRET
            | encryption::layout::TYPE_LOCAL_HISTORY_NODE_SECRET
            | encryption::layout::TYPE_LOCAL_RECIPIENT_KEY
            | transit_received::layout::TYPE_TRANSIT_RECEIVED
    )
}

pub fn seal_connection_send_frame(
    connection_id: FactId,
    fact_ids: &[FactId],
    connection_fact: &Fact,
    facts: &[&Fact],
) -> Result<Vec<u8>, String> {
    if connection_fact.id != connection_id {
        return Err("send_on_connection connection fact id mismatch".to_string());
    }
    if fact_ids.len() != facts.len() {
        return Err("send_on_connection fact id list does not match loaded facts".to_string());
    }
    let connection = connection_response::layout::decode_fact(&connection_fact.bytes)?;

    let mut bundle = TransitFactBundle::new();
    for (expected_id, fact) in fact_ids.iter().zip(facts.iter().copied()) {
        if fact.id != *expected_id {
            return Err("send_on_connection loaded fact id mismatch".to_string());
        }
        bundle.push(require_sendable_fact(fact)?.to_vec());
    }

    frame::seal_connection_frame(SealConnectionFrame {
        connection_id,
        sender_endpoint_id: connection.from_endpoint,
        receiver_endpoint_id: connection.to_endpoint,
        connection_secret: connection.connection_secret,
        nonce: frame::connection_send_nonce(connection_id, fact_ids),
        facts: bundle,
    })
}
