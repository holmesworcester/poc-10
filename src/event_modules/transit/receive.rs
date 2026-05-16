//! Admission rules for facts opened from inbound transit frames.
//!
//! The receive handler owns retrying the effect. This module owns the
//! protocol-level meaning of an opened frame: which inner fact types can be
//! admitted, how they are scoped, and which local provenance fact records the
//! receive.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::event_modules::{connection_response, encryption, signed_fact, transit_received};

use super::frame;

#[derive(Debug, Clone)]
pub struct OpenReceivedFrame<'a> {
    pub frame: &'a [u8],
    pub connection_fact: &'a Fact,
    pub origin_addr: &'a [u8],
    pub received_at_local_ms: u64,
}

pub fn open_received_frame(input: OpenReceivedFrame<'_>) -> Result<Vec<Fact>, String> {
    let connection = connection_response::layout::decode_fact(&input.connection_fact.bytes)?;
    let opened = frame::open_connection_frame(input.frame, &connection.connection_secret)?;
    if input.connection_fact.id != opened.connection_id {
        return Err("transit frame connection id does not match connection fact".to_string());
    }
    require_connection_endpoints(
        &connection,
        opened.sender_endpoint_id,
        opened.receiver_endpoint_id,
    )?;

    let mut facts = Vec::with_capacity(opened.facts.len() * 2);
    for bytes in opened.facts {
        let received = admit_received_fact_bytes(bytes)?;
        let provenance = received_provenance_fact(
            received.id,
            input.origin_addr,
            opened.receiver_endpoint_id,
            opened.sender_endpoint_id,
            opened.connection_id,
            connection.request_id,
            opened.frame_hash,
            input.received_at_local_ms,
        )?;
        facts.push(received);
        facts.push(provenance);
    }
    Ok(facts)
}

fn admit_received_fact_bytes(bytes: Vec<u8>) -> Result<Fact, String> {
    let tag = bytes
        .first()
        .copied()
        .ok_or_else(|| "received transit fact bytes are empty".to_string())?;
    if tag != signed_fact::layout::TYPE_SIGNED_FACT {
        return Err(format!("unsupported received transit fact type {tag}"));
    }

    let envelope = signed_fact::layout::decode_signed_fact(&bytes)?;
    match envelope.inner_type {
        encryption::layout::TYPE_KEY_WRAP => encryption::create::admit_signed_key_wrap_fact(bytes),
        other => Err(format!("unsupported signed transit payload type {other}")),
    }
}

fn received_provenance_fact(
    received_fact_id: FactId,
    origin_addr: &[u8],
    local_endpoint_id: FactId,
    sender_endpoint_id: FactId,
    connection_id: FactId,
    request_id: FactId,
    frame_hash: [u8; 32],
    received_at_local_ms: u64,
) -> Result<Fact, String> {
    let fact = transit_received::fact::TransitReceivedFact {
        received_fact_id,
        origin_addr: origin_addr.to_vec(),
        local_endpoint_id,
        sender_endpoint_id,
        transit_kind: transit_received::fact::TRANSIT_KIND_CONNECTION,
        connection_id: Some(connection_id),
        request_id: Some(request_id),
        frame_hash,
        received_at_local_ms,
    };
    Ok(Fact::new(
        FactScope::Local,
        received_at_local_ms,
        transit_received::layout::encode_fact(&fact)?,
    ))
}

fn require_connection_endpoints(
    connection: &connection_response::fact::ConnectionResponseFact,
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
) -> Result<(), String> {
    let forward = sender_endpoint_id == connection.from_endpoint
        && receiver_endpoint_id == connection.to_endpoint;
    let reverse = sender_endpoint_id == connection.to_endpoint
        && receiver_endpoint_id == connection.from_endpoint;
    if forward || reverse {
        Ok(())
    } else {
        Err("transit frame endpoints do not match connection fact".to_string())
    }
}
