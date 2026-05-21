//! Receive transit frame intent layout.
//!
//! Receive-transit handlers own decoding an inbound transit frame, verifying
//! the public envelope, and emitting the recovered inner fact for admission.
//! The intent payload carries the opaque outer frame bytes plus normalized local
//! receive metadata; cryptographic material is loaded from fact context.

use crate::core::intents::{Intent, IntentKind};
use crate::protocol::facts::transport::transit_received::addr::normalize_origin_addr_bytes;
use crate::protocol::intents::payload::{PayloadError, PayloadReader, PayloadWriter};

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
// Decodes the receive intent, asks the transport::transit fact module which exact
// connection fact is needed, and returns the opened shared/local facts that
// core should admit.

use crate::core::intents::{
    HandlerContext, HandlerError, HandlerFactId, HandlerOutput, HandlerResult, IntentHandler,
};
use crate::protocol::facts::{
    identity::endpoint,
    transport::transit::{
        frame,
        receive::{
            self, BootstrapFrameKind, OpenBootstrapRequest, OpenBootstrapResponse,
            OpenReceivedFrame,
        },
    },
};

#[derive(Debug, Clone, Default)]
pub struct ReceiveTransitFrameHandler;

impl ReceiveTransitFrameHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for ReceiveTransitFrameHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_receive_transit_frame(intent)?;
        match receive::bootstrap_frame_kind(&input.frame)? {
            BootstrapFrameKind::ConnectionRequest(request) => {
                Ok(vec![request.invite_secret_fact_id])
            }
            BootstrapFrameKind::ConnectionResponse(response) => Ok(vec![
                response.request_id,
                response.invite_secret_fact_id,
                response.initiator_ephemeral_secret_fact_id,
            ]),
            BootstrapFrameKind::ConnectionFrame => {
                Ok(vec![frame::received_connection_fact_id(&input.frame)?])
            }
        }
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_receive_transit_frame(intent)?;
        let facts = match receive::bootstrap_frame_kind(&input.frame)? {
            BootstrapFrameKind::ConnectionRequest(request) => {
                let invite_fact = context.require_fact(&request.invite_secret_fact_id)?;
                let local_endpoint = endpoint::local_endpoint::local_endpoint(context.store()?)?
                    .ok_or_else(|| {
                        HandlerError::fatal("bootstrap request receiver has no local endpoint")
                    })?;
                let opened = receive::open_bootstrap_request(OpenBootstrapRequest {
                    frame: &input.frame,
                    invite_fact,
                    local_endpoint: &local_endpoint,
                    origin_addr: &input.origin_addr,
                    received_at_local_ms: input.received_at_local_ms,
                })?;
                opened.facts
            }
            BootstrapFrameKind::ConnectionResponse(_) => {
                receive::open_bootstrap_response(OpenBootstrapResponse {
                    frame: &input.frame,
                    origin_addr: &input.origin_addr,
                    received_at_local_ms: input.received_at_local_ms,
                })?
            }
            BootstrapFrameKind::ConnectionFrame => {
                let connection_id = frame::received_connection_fact_id(&input.frame)?;
                let connection_fact = context.require_fact(&connection_id)?;
                receive::open_received_frame(OpenReceivedFrame {
                    frame: &input.frame,
                    connection_fact,
                    origin_addr: &input.origin_addr,
                    received_at_local_ms: input.received_at_local_ms,
                })?
            }
        };
        let mut output = HandlerOutput::new();
        for fact in facts {
            output = output.fact(fact);
        }
        Ok(output)
    }
}
