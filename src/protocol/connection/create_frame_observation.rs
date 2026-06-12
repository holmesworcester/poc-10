//! Create a connection-frame observation fact.
//!
//! `receive_network_frame` owns socket normalization and frame classification.
//! This intent owns the follow-up construction of the local
//! `connection_frame_observation` fact, keeping observation authoring beside
//! the fact family instead of inside frame helpers.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{
    HandlerContext, HandlerFactId, HandlerResult, Intent, IntentHandler, IntentKind,
};
use crate::core::wire::{
    Reader as PayloadReader, WireError as PayloadError, Writer as PayloadWriter,
};
use crate::protocol::connection::frame_observation;

pub const CREATE_FRAME_OBSERVATION: &str = "create_frame_observation";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFrameObservation {
    pub frame_fact_id: [u8; 32],
    pub origin_addr: Vec<u8>,
    pub received_at_local_ms: u64,
}

pub fn create_frame_observation_intent(input: CreateFrameObservation) -> Intent {
    let mut payload = PayloadWriter::with_capacity(32 + 4 + input.origin_addr.len() + 8);
    payload.fixed(&input.frame_fact_id);
    payload
        .bytes_u32be(&input.origin_addr)
        .expect("create_frame_observation origin addr fits u32");
    payload.u64be(input.received_at_local_ms);
    Intent::new(
        IntentKind::new(CREATE_FRAME_OBSERVATION).expect("valid create_frame_observation kind"),
        create_frame_observation_key(&input),
        payload.finish(),
    )
}

pub fn decode_create_frame_observation(intent: &Intent) -> Result<CreateFrameObservation, String> {
    if intent.kind.as_str() != CREATE_FRAME_OBSERVATION {
        return Err("expected create_frame_observation intent".into());
    }
    let mut reader = PayloadReader::new(&intent.payload);
    let frame_fact_id = reader.array::<32>().map_err(payload_error)?;
    let origin_addr = reader.bytes_u32be().map_err(payload_error)?.to_vec();
    let received_at_local_ms = reader.u64be().map_err(payload_error)?;
    reader.finish().map_err(payload_error)?;
    let input = CreateFrameObservation {
        frame_fact_id,
        origin_addr,
        received_at_local_ms,
    };
    if intent.key != create_frame_observation_key(&input) {
        return Err("create_frame_observation idempotence key does not match payload".into());
    }
    Ok(input)
}

fn create_frame_observation_key(input: &CreateFrameObservation) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:create-frame-observation:v1:");
    hash.update(&input.frame_fact_id);
    hash.update(&(input.origin_addr.len() as u32).to_be_bytes());
    hash.update(&input.origin_addr);
    hash.update(&input.received_at_local_ms.to_be_bytes());
    hash.finalize().as_bytes().to_vec()
}

fn payload_error(err: PayloadError) -> String {
    format!("invalid create_frame_observation payload: {err}")
}

#[derive(Debug, Clone, Default)]
pub struct CreateFrameObservationHandler;

impl CreateFrameObservationHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for CreateFrameObservationHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        decode_create_frame_observation(intent)?;
        Ok(Vec::new())
    }

    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> HandlerResult {
        let input = decode_create_frame_observation(intent)?;
        Ok(
            PipelineEffects::new().fact(frame_observation::author::fact_from_observation(
                input.frame_fact_id,
                &input.origin_addr,
                input.received_at_local_ms,
            )?),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_frame_observation_intent_round_trips() {
        let input = CreateFrameObservation {
            frame_fact_id: [1; 32],
            origin_addr: b"127.0.0.1:41000".to_vec(),
            received_at_local_ms: 55,
        };
        let intent = create_frame_observation_intent(input.clone());

        assert_eq!(
            decode_create_frame_observation(&intent).expect("decode"),
            input
        );
    }
}
