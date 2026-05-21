//! Package exact facts into one connection transit frame.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{
    HandlerContext, HandlerError, HandlerFactId, HandlerResult, IntentHandler,
};
use crate::core::intents::{Intent, IntentKind};
use crate::protocol::facts::{
    connection::response,
    identity::endpoint,
    transport::transit::{
        create,
        frame::{self, TransitFactBundle},
    },
};
use crate::protocol::intents::payload::{PayloadError, PayloadReader, PayloadWriter};
use crate::protocol::intents::transport::send_network_frame::{self, SendNetworkFrame};

pub type HandlerId = [u8; 32];

pub const SEND_FACTS_ON_CONNECTION: &str = "send_facts_on_connection";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFactsOnConnection {
    pub connection_id: HandlerId,
    /// Ordered fact ids that must travel together for the receiver to project
    /// the requested range item without a follow-up key/dependency round trip.
    pub fact_ids: Vec<HandlerId>,
}

pub fn send_facts_on_connection_intent(input: SendFactsOnConnection) -> Intent {
    let mut payload = PayloadWriter::with_capacity(37 + input.fact_ids.len() * 32);
    payload.u8(1);
    payload.fixed(&input.connection_id);
    payload.u32be(
        input
            .fact_ids
            .len()
            .try_into()
            .expect("fact id count fits u32"),
    );
    for fact_id in &input.fact_ids {
        payload.fixed(fact_id);
    }

    Intent::new(
        IntentKind::new(SEND_FACTS_ON_CONNECTION).expect("valid send_facts_on_connection kind"),
        connection_fact_ids_key(input.connection_id, &input.fact_ids),
        payload.finish(),
    )
}

pub fn decode_send_facts_on_connection(intent: &Intent) -> Result<SendFactsOnConnection, String> {
    if intent.kind.as_str() != SEND_FACTS_ON_CONNECTION {
        return Err("expected send_facts_on_connection intent".into());
    }
    let mut reader = PayloadReader::new(&intent.payload);
    reader.expect_u8(1).map_err(payload_error)?;
    let connection_id = reader.array::<32>().map_err(payload_error)?;
    let count = reader.u32be().map_err(payload_error)? as usize;
    let mut fact_ids = Vec::with_capacity(count);
    for _ in 0..count {
        fact_ids.push(reader.array::<32>().map_err(payload_error)?);
    }
    reader.finish().map_err(payload_error)?;
    if fact_ids.is_empty() {
        return Err("send_facts_on_connection must name at least one fact".into());
    }
    if intent.key != connection_fact_ids_key(connection_id, &fact_ids) {
        return Err("send_facts_on_connection key does not match payload".into());
    }
    Ok(SendFactsOnConnection {
        connection_id,
        fact_ids,
    })
}

fn connection_fact_ids_key(connection_id: HandlerId, fact_ids: &[HandlerId]) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:send-facts-on-connection:v1:");
    hash.update(&connection_id);
    for fact_id in fact_ids {
        hash.update(fact_id);
    }
    hash.finalize().as_bytes().to_vec()
}

fn payload_error(err: PayloadError) -> String {
    format!("invalid send_facts_on_connection payload: {err}")
}

#[derive(Debug, Clone, Default)]
pub struct SendFactsOnConnectionHandler;

impl SendFactsOnConnectionHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SendFactsOnConnectionHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_send_facts_on_connection(intent)?;
        let mut ids = Vec::with_capacity(1 + input.fact_ids.len());
        ids.push(input.connection_id);
        ids.extend(input.fact_ids);
        Ok(ids)
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_send_facts_on_connection(intent)?;
        let connection_fact = context.require_fact(&input.connection_id)?;
        let connection = response::layout::decode_fact(connection_fact.body())?;
        if connection_fact.id != input.connection_id {
            return Err("send_facts_on_connection connection fact id mismatch".into());
        }

        let mut facts = TransitFactBundle::new();
        for fact_id in &input.fact_ids {
            let fact = context.require_fact(fact_id)?;
            facts.push(create::require_sendable_fact(fact)?.to_vec());
        }

        let local_endpoint = endpoint::local_endpoint::local_endpoint(context.store()?)?
            .ok_or_else(|| {
                HandlerError::fatal("send_facts_on_connection requires local endpoint state")
            })?;
        let (sender_endpoint, receiver_endpoint) = if local_endpoint.endpoint
            == connection.from_endpoint
        {
            (connection.from_endpoint, connection.to_endpoint)
        } else if local_endpoint.endpoint == connection.to_endpoint {
            (connection.to_endpoint, connection.from_endpoint)
        } else {
            return Err("send_facts_on_connection local endpoint is not part of connection".into());
        };

        let frame = frame::seal_connection_send_frame(
            input.connection_id,
            sender_endpoint,
            receiver_endpoint,
            connection.connection_secret,
            &input.fact_ids,
            facts,
        )?;

        Ok(
            PipelineEffects::new().local_intent(send_network_frame::send_network_frame_intent(
                SendNetworkFrame {
                    routing_key: input.connection_id,
                    frame,
                },
            )),
        )
    }
}
