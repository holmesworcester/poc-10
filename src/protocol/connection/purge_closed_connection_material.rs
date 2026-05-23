//! Bounded purge handler for closed connection-private material.
//!
//! Target projectors emit this intent after observing validated close context.
//! The idempotence key orders ephemeral-secret targets before the connection
//! response target, so secret purge validation can still read the response fact
//! that names the allowed ephemeral ids.
//!
//! The handler revalidates the close fact, connection response, and target fact
//! before purging. Row deletion belongs to the fact projectors that own those
//! rows; this handler only removes the closed fact material after projection
//! has consumed the close context.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{
    HandlerContext, HandlerFactId, HandlerResult, Intent, IntentHandler, IntentKind,
};

use crate::protocol::connection::{close, ephemeral_secret, response};

pub const PURGE_CLOSED_CONNECTION_MATERIAL: &str = "purge_closed_connection_material";

const VERSION: u8 = 1;
pub const TARGET_EPHEMERAL_SECRET: u8 = 0;
pub const TARGET_CONNECTION_RESPONSE: u8 = 1;
const PAYLOAD_BYTES: usize = 1 + 1 + 32 + 32 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeClosedConnectionMaterial {
    pub target_kind: u8,
    pub close_id: HandlerFactId,
    pub connection_id: HandlerFactId,
    pub target_id: HandlerFactId,
}

pub fn purge_closed_connection_material_intent(input: PurgeClosedConnectionMaterial) -> Intent {
    Intent::new(
        IntentKind::new(PURGE_CLOSED_CONNECTION_MATERIAL)
            .expect("valid purge_closed_connection_material intent kind"),
        purge_closed_connection_material_key(&input),
        encode_purge_closed_connection_material(&input),
    )
}

pub fn decode_purge_closed_connection_material(
    intent: &Intent,
) -> Result<PurgeClosedConnectionMaterial, String> {
    if intent.kind.as_str() != PURGE_CLOSED_CONNECTION_MATERIAL {
        return Err("expected purge_closed_connection_material intent".to_string());
    }
    let input = decode_purge_closed_connection_material_payload(&intent.payload)?;
    if intent.key != purge_closed_connection_material_key(&input) {
        return Err("purge_closed_connection_material key does not match payload".to_string());
    }
    validate_target_kind(input.target_kind)?;
    Ok(input)
}

fn purge_closed_connection_material_key(input: &PurgeClosedConnectionMaterial) -> Vec<u8> {
    let mut key = Vec::with_capacity(65);
    key.push(input.target_kind);
    key.extend_from_slice(&input.connection_id);
    key.extend_from_slice(&input.target_id);
    key
}

fn encode_purge_closed_connection_material(input: &PurgeClosedConnectionMaterial) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PAYLOAD_BYTES);
    payload.push(VERSION);
    payload.push(input.target_kind);
    payload.extend_from_slice(&input.close_id);
    payload.extend_from_slice(&input.connection_id);
    payload.extend_from_slice(&input.target_id);
    payload
}

fn decode_purge_closed_connection_material_payload(
    payload: &[u8],
) -> Result<PurgeClosedConnectionMaterial, String> {
    if payload.len() != PAYLOAD_BYTES || payload[0] != VERSION {
        return Err("invalid purge_closed_connection_material payload".to_string());
    }
    Ok(PurgeClosedConnectionMaterial {
        target_kind: payload[1],
        close_id: payload[2..34].try_into().unwrap(),
        connection_id: payload[34..66].try_into().unwrap(),
        target_id: payload[66..98].try_into().unwrap(),
    })
}

fn validate_target_kind(target_kind: u8) -> Result<(), String> {
    match target_kind {
        TARGET_EPHEMERAL_SECRET | TARGET_CONNECTION_RESPONSE => Ok(()),
        _ => Err("purge_closed_connection_material target kind is unsupported".to_string()),
    }
}

#[derive(Debug, Clone, Default)]
pub struct PurgeClosedConnectionMaterialHandler;

impl PurgeClosedConnectionMaterialHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for PurgeClosedConnectionMaterialHandler {
    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_purge_closed_connection_material(raw_intent)?;
        Ok(vec![input.close_id, input.connection_id, input.target_id])
    }

    fn handle(&self, raw_intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_purge_closed_connection_material(raw_intent)?;
        let close_fact = context.require_fact(&input.close_id)?;
        let connection_fact = context.require_fact(&input.connection_id)?;
        let close = close::decode_fact_payload(close_fact.body())?;
        let connection = response::decode_fact_payload(connection_fact.body())?;
        if close.connection_id != input.connection_id {
            return Err("purge_closed_connection_material close targets another connection".into());
        }
        if connection_fact.id != input.connection_id {
            return Err("purge_closed_connection_material connection id mismatch".into());
        }

        match input.target_kind {
            TARGET_EPHEMERAL_SECRET => {
                let target = context.require_fact(&input.target_id)?;
                ephemeral_secret::decode_fact_payload(target.body())?;
                if input.target_id != connection.initiator_ephemeral_secret_fact_id
                    && input.target_id != connection.responder_ephemeral_secret_fact_id
                {
                    return Err(
                        "purge_closed_connection_material ephemeral target is not on connection"
                            .into(),
                    );
                }
                Ok(PipelineEffects::new().purge_fact(input.target_id))
            }
            TARGET_CONNECTION_RESPONSE => {
                if input.target_id != input.connection_id {
                    return Err(
                        "purge_closed_connection_material response target id mismatch".into(),
                    );
                }
                Ok(PipelineEffects::new().purge_fact(input.connection_id))
            }
            _ => Err("purge_closed_connection_material target kind is unsupported".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_roundtrips_and_orders_ephemeral_before_response() {
        let close_id = [1; 32];
        let connection_id = [2; 32];
        let ephemeral = purge_closed_connection_material_intent(PurgeClosedConnectionMaterial {
            target_kind: TARGET_EPHEMERAL_SECRET,
            close_id,
            connection_id,
            target_id: [3; 32],
        });
        let response = purge_closed_connection_material_intent(PurgeClosedConnectionMaterial {
            target_kind: TARGET_CONNECTION_RESPONSE,
            close_id,
            connection_id,
            target_id: connection_id,
        });

        assert_eq!(
            decode_purge_closed_connection_material(&ephemeral).unwrap(),
            PurgeClosedConnectionMaterial {
                target_kind: TARGET_EPHEMERAL_SECRET,
                close_id,
                connection_id,
                target_id: [3; 32],
            }
        );
        assert!(ephemeral.key < response.key);
    }
}
