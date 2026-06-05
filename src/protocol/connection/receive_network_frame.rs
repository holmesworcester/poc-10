//! Inbound network-frame intent.
//!
//! The daemon turns each accepted TCP frame into this local intent with the raw
//! bytes, observed origin address, and local receive time. The handler decodes
//! and validates that boundary metadata, stages sealed handshake request or
//! response facts (bootstrap and membership alike), then delegates durable fact
//! admission to fact projectors; it does not open frames or validate child
//! facts itself.
//!
//! The intent key is deterministic over origin, receive time, and frame bytes
//! so duplicate local submissions collapse while distinct observations remain
//! separate. Change this file for receive-intent payload shape, metadata
//! normalization, or the choice of which received-frame fact family should
//! stage an established connection frame.

use crate::core::intents::{Intent, IntentKind};
use crate::protocol::connection::fact_receipt::author::normalize_origin_addr_bytes;
use crate::protocol::payload::{PayloadError, PayloadReader, PayloadWriter};

pub const RECEIVE_NETWORK_FRAME: &str = "receive_network_frame";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveNetworkFrame {
    /// Raw bytes as received from the network. These are sealed bootstrap
    /// request frames, sealed bootstrap response frames, or encrypted
    /// established-connection frames.
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
// Sealed handshake frames carry no separate envelope fact: the handler admits
// the sealed bytes as their own ephemeral fact (whose type tag is the sealed
// type) plus a frame observation, and does no unsealing itself. That fact's
// projector opens it with the local endpoint secret drawn from
// `auth_local_endpoint` context and emits the recovered request/connection fact
// plus its receive receipt. Opening is transport decoding, not protocol
// validation; the request and connection projectors still own
// invite/membership/handshake validation.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
use crate::protocol::connection::{
    connection, frame_bundle, frame_file_slice, frame_small, request,
};
use crate::protocol::connection_frame::{self, ConnectionFrameKind};

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

        // A sealed handshake frame is admitted as its own ephemeral fact (whose
        // type tag is the sealed type) plus a frame observation. Its projector
        // unseals it with the local endpoint secret from `auth_local_endpoint`
        // context — the boundary does no unsealing itself.
        if request::decode::is_sealed_fact(&input.frame) {
            return Ok(connection_frame::observed_request_fact_effect(
                input.frame.clone(),
                &input.origin_addr,
                input.received_at_local_ms,
            )?);
        }
        if connection::decode::is_sealed_fact(&input.frame) {
            return Ok(connection_frame::observed_connection_fact_effect(
                input.frame.clone(),
                &input.origin_addr,
                input.received_at_local_ms,
            )?);
        }

        Ok(match connection_frame::classify_frame(&input.frame) {
            Some(ConnectionFrameKind::Small) => connection_frame::observed_frame_effect(
                frame_small::author::fact_from_wire(&input.frame, input.received_at_local_ms)?,
                &input.origin_addr,
                input.received_at_local_ms,
            )?,
            Some(ConnectionFrameKind::FileSlice) => connection_frame::observed_frame_effect(
                frame_file_slice::author::fact_from_wire(&input.frame, input.received_at_local_ms)?,
                &input.origin_addr,
                input.received_at_local_ms,
            )?,
            Some(ConnectionFrameKind::Bundle) => connection_frame::observed_frame_effect(
                frame_bundle::author::fact_from_wire(&input.frame, input.received_at_local_ms)?,
                &input.origin_addr,
                input.received_at_local_ms,
            )?,
            None => PipelineEffects::new(),
        })
    }
}
