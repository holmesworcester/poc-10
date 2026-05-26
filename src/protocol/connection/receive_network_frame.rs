//! Inbound network-frame intent.
//!
//! The daemon turns each accepted TCP frame into this local intent with the raw
//! bytes, observed origin address, and local receive time. The handler decodes
//! and validates that boundary metadata, opens sealed bootstrap wrappers with
//! local endpoint material, then delegates durable fact admission to
//! `connection::frame::create`; it does not open established frames or validate
//! child facts itself.
//!
//! The intent key is deterministic over origin, receive time, and frame bytes
//! so duplicate local submissions collapse while distinct observations remain
//! separate. Change this file for receive-intent payload shape or metadata
//! normalization. Change `connection::frame` for protocol byte classification.

use crate::core::intents::{Intent, IntentKind};
use crate::protocol::connection::fact_receipt::create::normalize_origin_addr_bytes;
use crate::protocol::payload::{PayloadError, PayloadReader, PayloadWriter};

pub const RECEIVE_NETWORK_FRAME: &str = "receive_network_frame";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveNetworkFrame {
    /// Raw bytes as received from the network. These are sealed bootstrap
    /// request/response wrappers or encrypted established-connection frames.
    pub frame: Vec<u8>,
    /// Observed local origin string, usually the peer socket address. Accepted
    /// boundary input is normalized before the intent is queued or handled.
    pub origin_addr: Vec<u8>,
    /// Local receive time used only for the local fact-receipt fact.
    pub received_at_local_ms: u64,
}

pub fn receive_network_frame_intent(input: ReceiveNetworkFrame) -> Result<Intent, String> {
    let input = normalized_input(input)?;
    let mut payload =
        PayloadWriter::with_capacity(16 + input.origin_addr.len() + input.frame.len());
    payload
        .bytes_u32be(&input.origin_addr)
        .expect("origin addr fits u32");
    payload.u64be(input.received_at_local_ms);
    payload
        .bytes_u32be(&input.frame)
        .expect("network frame fits u32");
    Ok(Intent::new(
        IntentKind::new(RECEIVE_NETWORK_FRAME).expect("valid receive_network_frame intent kind"),
        receive_network_key(&input),
        payload.finish(),
    ))
}

pub fn decode_receive_network_frame(intent: &Intent) -> Result<ReceiveNetworkFrame, String> {
    if intent.kind.as_str() != RECEIVE_NETWORK_FRAME {
        return Err("expected receive_network_frame intent".into());
    }

    let mut reader = PayloadReader::new(&intent.payload);
    let origin_addr = normalize_origin_addr_bytes(reader.bytes_u32be().map_err(payload_error)?)?;
    let received_at_local_ms = reader.u64be().map_err(payload_error)?;
    let frame = reader.bytes_u32be().map_err(payload_error)?.to_vec();
    reader.finish().map_err(payload_error)?;

    let input = ReceiveNetworkFrame {
        frame,
        origin_addr,
        received_at_local_ms,
    };
    if intent.key != receive_network_key(&input) {
        return Err("receive_network_frame idempotence key does not match payload".into());
    }
    Ok(input)
}

fn normalized_input(mut input: ReceiveNetworkFrame) -> Result<ReceiveNetworkFrame, String> {
    input.origin_addr = normalize_origin_addr_bytes(&input.origin_addr)?;
    Ok(input)
}

fn receive_network_key(input: &ReceiveNetworkFrame) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:receive-network-frame:v1:");
    hash.update(&(input.origin_addr.len() as u32).to_be_bytes());
    hash.update(&input.origin_addr);
    hash.update(&input.received_at_local_ms.to_be_bytes());
    hash.update(&(input.frame.len() as u32).to_be_bytes());
    hash.update(&input.frame);
    hash.finalize().as_bytes().to_vec()
}

fn payload_error(err: PayloadError) -> String {
    format!("invalid receive_network_frame payload: {err}")
}

// The handler is the incoming socket boundary. It has no input facts because
// raw network bytes are not authorized by durable context until projection.

use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
use crate::protocol::connection::bootstrap::create::{
    is_bootstrap_frame, received_bootstrap_frame_effect,
};
use crate::protocol::connection::frame::create::{
    received_network_frame_effect, ReceivedNetworkFrame as ClassifiedNetworkFrame,
};

#[derive(Debug, Clone, Default)]
pub struct ReceiveNetworkFrameHandler;

impl ReceiveNetworkFrameHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for ReceiveNetworkFrameHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        decode_receive_network_frame(intent)?;
        Ok(Vec::new())
    }

    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> HandlerResult {
        let input = decode_receive_network_frame(intent)?;
        if is_bootstrap_frame(&input.frame) {
            if let Some(effects) = received_bootstrap_frame_effect(
                &input.frame,
                &input.origin_addr,
                input.received_at_local_ms,
            )? {
                return Ok(effects);
            }
        }
        Ok(received_network_frame_effect(ClassifiedNetworkFrame {
            frame: &input.frame,
            origin_addr: &input.origin_addr,
            received_at_local_ms: input.received_at_local_ms,
        })?)
    }
}
