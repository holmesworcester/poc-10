//! Inbound network-frame intake.
//!
//! The daemon turns each accepted TCP frame into this boundary input with the
//! raw bytes, observed origin address, and local receive time. This module
//! decodes and validates that boundary metadata, admits sealed handshake
//! request, response, or established-frame bytes into the appropriate incoming
//! fact queue, then delegates fact admission to projectors; it does not open
//! frames or validate child facts itself.
//!
//! The intent key is deterministic over origin, receive time, and frame bytes
//! so duplicate local submissions collapse while distinct observations remain
//! separate when this boundary is exercised through the generic handler
//! interface. Change this file for receive payload shape, metadata
//! normalization, or the choice of which received-frame fact family should
//! stage an established connection frame.

use crate::core::intents::{Intent, IntentKind};
use crate::core::wire::{
    Reader as PayloadReader, WireError as PayloadError, Writer as PayloadWriter,
};
use crate::protocol::connection::fact_receipt::fact::normalize_origin_addr_bytes;

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

// This module is the incoming socket boundary. It has no input facts because
// raw network bytes are not authorized by context until projection. Sealed
// handshake frames carry no separate envelope fact: intake stages the bytes as
// their own local incoming fact (whose type tag selects the owning
// projector) plus a frame observation. Established connection frames use the
// same incoming path. The boundary does no unsealing itself. The selected
// projector opens bytes with context and emits recovered child facts plus
// receive receipts. Opening is transport decoding, not protocol validation; the
// child projectors still own semantic validation and retention.

use crate::core;
use crate::core::effects::RuntimeEffects;
use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
use crate::protocol::connection::{
    connection, frame_bundle, frame_file_slice, frame_observation, frame_small, request,
};

pub fn receive_network_frame_effects(input: ReceiveNetworkFrame) -> Result<RuntimeEffects, String> {
    let input = normalized_input(input)?;
    let observed_incoming = |frame_fact: core::facts::Fact| -> Result<RuntimeEffects, String> {
        let observation = frame_observation::author::fact_from_observation(
            frame_fact.id,
            &input.origin_addr,
            input.received_at_local_ms,
        )?;
        Ok(RuntimeEffects::new()
            .fact(observation)
            .incoming_fact(frame_fact))
    };

    // A sealed handshake frame is admitted as its own local fact (whose type
    // tag is the sealed type) plus a frame observation. Its projector unseals it
    // with the local endpoint secret from `auth_local_endpoint` context; the
    // boundary does no unsealing itself.
    if request::project::decode::is_sealed_fact(&input.frame) {
        let fact =
            request::author::fact_from_sealed_wire(&input.frame, input.received_at_local_ms)?;
        return observed_incoming(fact);
    }
    if connection::project::decode::is_sealed_fact(&input.frame) {
        let fact =
            connection::author::fact_from_sealed_wire(&input.frame, input.received_at_local_ms)?;
        return observed_incoming(fact);
    }

    if frame_small::project::decode::is_frame(&input.frame) {
        observed_incoming(frame_small::author::fact_from_wire(
            &input.frame,
            input.received_at_local_ms,
        )?)
    } else if frame_file_slice::project::decode::is_frame(&input.frame) {
        observed_incoming(frame_file_slice::author::fact_from_wire(
            &input.frame,
            input.received_at_local_ms,
        )?)
    } else if frame_bundle::project::decode::is_frame(&input.frame) {
        observed_incoming(frame_bundle::author::fact_from_wire(
            &input.frame,
            input.received_at_local_ms,
        )?)
    } else {
        Ok(RuntimeEffects::new())
    }
}

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

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_receive_network_frame(intent)?;
        if context.is_replay() {
            return Ok(RuntimeEffects::new());
        }
        Ok(receive_network_frame_effects(input)?)
    }
}
