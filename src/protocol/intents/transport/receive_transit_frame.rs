//! Receive transit frame intent layout.
//!
//! Receive-transit handlers own decoding an inbound transit frame, verifying
//! the public envelope, and emitting the recovered inner fact for admission.
//! The intent payload carries the opaque outer frame bytes plus normalized local
//! receive metadata; cryptographic material is loaded from fact context.

use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::protocol::facts::transport::transit_received::addr::normalize_origin_addr_bytes;

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
    let mut payload = Vec::with_capacity(16 + input.origin_addr.len() + input.frame.len());
    push_bytes(&mut payload, &input.origin_addr);
    payload.extend_from_slice(&input.received_at_local_ms.to_be_bytes());
    push_bytes(&mut payload, &input.frame);
    Ok(Intent::new(
        IntentKind::new(RECEIVE_TRANSIT_FRAME).expect("valid receive_transit_frame intent kind"),
        IntentExecution::Deferred,
        receive_transit_key(&input),
        payload,
    ))
}

pub fn decode_receive_transit_frame(intent: &Intent) -> Result<ReceiveTransitFrame, String> {
    if intent.kind.as_str() != RECEIVE_TRANSIT_FRAME {
        return Err("expected receive_transit_frame intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("receive_transit_frame intent must be deferred".to_string());
    }

    let mut reader = Reader::new(&intent.payload);
    let origin_addr = normalize_origin_addr_bytes(reader.bytes()?)?;
    let received_at_local_ms = reader.u64()?;
    let frame = reader.bytes()?.to_vec();
    reader.finish()?;

    let input = ReceiveTransitFrame {
        frame,
        origin_addr,
        received_at_local_ms,
    };
    if intent.key != receive_transit_key(&input) {
        return Err("receive_transit_frame idempotence key does not match payload".to_string());
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

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "intent payload length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated intent payload".to_string());
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err("intent payload has trailing bytes".to_string())
        }
    }
}

// Handler for inbound transit frame admission.
//
// Decodes the receive intent, asks the transport::transit fact module which exact
// connection fact is needed, and returns the opened shared/local facts that
// core should admit.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
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
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == RECEIVE_TRANSIT_FRAME
    }

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

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_receive_transit_frame(intent)?;
        let facts = match receive::bootstrap_frame_kind(&input.frame)? {
            BootstrapFrameKind::ConnectionRequest(request) => {
                let invite_fact = context.require_fact(&request.invite_secret_fact_id)?;
                let local_endpoint = endpoint::local_endpoint::local_endpoint(context.store()?)?
                    .ok_or_else(|| {
                        "bootstrap request receiver has no local endpoint".to_string()
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
