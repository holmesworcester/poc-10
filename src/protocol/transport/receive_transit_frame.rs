//! Receive transit frame intent layout.
//!
//! Receive-transit handlers own decoding inbound network metadata into a
//! transient projectable input. The intent payload carries the opaque outer
//! frame bytes plus normalized local receive metadata; frame classification and
//! cryptographic opening happen in the transit projector where durable context
//! is available.

use crate::core::intents::{Intent, IntentKind};
use crate::protocol::payload::{PayloadError, PayloadReader, PayloadWriter};
use crate::protocol::transport::transit_received::create::normalize_origin_addr_bytes;

pub const RECEIVE_TRANSIT_FRAME: &str = "receive_transit_frame";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveTransitFrame {
    /// Raw outer transport::transit frame bytes as received from the network. The handler
    /// peeks the public header and dispatches to the matching size class.
    pub frame: Vec<u8>,
    /// Observed local origin string, usually the peer socket address. Accepted
    /// boundary input is normalized before the intent is queued or handled.
    pub origin_addr: Vec<u8>,
    /// Local receive time used only for the local receive-provenance fact.
    pub received_at_local_ms: u64,
}

pub fn receive_transit_frame_intent(input: ReceiveTransitFrame) -> Result<Intent, String> {
    let input = normalized_input(input)?;
    let mut payload =
        PayloadWriter::with_capacity(16 + input.origin_addr.len() + input.frame.len());
    payload
        .bytes_u32be(&input.origin_addr)
        .expect("origin addr fits u32");
    payload.u64be(input.received_at_local_ms);
    payload
        .bytes_u32be(&input.frame)
        .expect("transit frame fits u32");
    Ok(Intent::new(
        IntentKind::new(RECEIVE_TRANSIT_FRAME).expect("valid receive_transit_frame intent kind"),
        receive_transit_key(&input),
        payload.finish(),
    ))
}

pub fn decode_receive_transit_frame(intent: &Intent) -> Result<ReceiveTransitFrame, String> {
    if intent.kind.as_str() != RECEIVE_TRANSIT_FRAME {
        return Err("expected receive_transit_frame intent".into());
    }

    let mut reader = PayloadReader::new(&intent.payload);
    let origin_addr = normalize_origin_addr_bytes(reader.bytes_u32be().map_err(payload_error)?)?;
    let received_at_local_ms = reader.u64be().map_err(payload_error)?;
    let frame = reader.bytes_u32be().map_err(payload_error)?.to_vec();
    reader.finish().map_err(payload_error)?;

    let input = ReceiveTransitFrame {
        frame,
        origin_addr,
        received_at_local_ms,
    };
    if intent.key != receive_transit_key(&input) {
        return Err("receive_transit_frame idempotence key does not match payload".into());
    }
    Ok(input)
}

fn normalized_input(mut input: ReceiveTransitFrame) -> Result<ReceiveTransitFrame, String> {
    input.origin_addr = normalize_origin_addr_bytes(&input.origin_addr)?;
    Ok(input)
}

fn receive_transit_key(input: &ReceiveTransitFrame) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:receive-transit-frame:v1:");
    hash.update(&(input.origin_addr.len() as u32).to_be_bytes());
    hash.update(&input.origin_addr);
    hash.update(&input.received_at_local_ms.to_be_bytes());
    hash.update(&(input.frame.len() as u32).to_be_bytes());
    hash.update(&input.frame);
    hash.finalize().as_bytes().to_vec()
}

fn payload_error(err: PayloadError) -> String {
    format!("invalid receive_transit_frame payload: {err}")
}

// Handler for inbound transit frame admission.
//
// Decodes the receive intent and emits one ephemeral transit input. Projection
// owns the one-shot context check and any durable child facts recovered from the
// frame.

use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
use crate::protocol::transport::transit::{create as transit_create, fact::TransitInputFact};

#[derive(Debug, Clone, Default)]
pub struct ReceiveTransitFrameHandler;

impl ReceiveTransitFrameHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for ReceiveTransitFrameHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        decode_receive_transit_frame(intent)?;
        Ok(Vec::new())
    }

    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> HandlerResult {
        let input = decode_receive_transit_frame(intent)?;
        Ok(transit_create::received_input_effect(TransitInputFact {
            frame: input.frame,
            origin_addr: input.origin_addr,
            received_at_local_ms: input.received_at_local_ms,
        })?)
    }
}
