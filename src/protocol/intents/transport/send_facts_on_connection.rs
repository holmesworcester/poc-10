//! Package exact facts into one connection transit frame.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::protocol::facts::{
    connection::response,
    identity::endpoint,
    transport::transit::{
        create,
        frame::{self, TransitFactBundle},
    },
};
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
    let mut payload = Vec::with_capacity(37 + input.fact_ids.len() * 32);
    payload.push(1);
    push_id(&mut payload, &input.connection_id);
    push_ids(&mut payload, &input.fact_ids);

    Intent::new(
        IntentKind::new(SEND_FACTS_ON_CONNECTION).expect("valid send_facts_on_connection kind"),
        IntentExecution::Deferred,
        connection_fact_ids_key(input.connection_id, &input.fact_ids),
        payload,
    )
}

pub fn decode_send_facts_on_connection(intent: &Intent) -> Result<SendFactsOnConnection, String> {
    if intent.kind.as_str() != SEND_FACTS_ON_CONNECTION {
        return Err("expected send_facts_on_connection intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("send_facts_on_connection intent must be deferred".to_string());
    }
    if intent.payload.len() < 37 || intent.payload[0] != 1 {
        return Err("send_facts_on_connection payload is malformed".to_string());
    }
    let mut reader = Reader::new(&intent.payload[1..]);
    let connection_id = reader.id()?;
    let fact_ids = reader.ids()?;
    reader.finish()?;
    if fact_ids.is_empty() {
        return Err("send_facts_on_connection must name at least one fact".to_string());
    }
    if intent.key != connection_fact_ids_key(connection_id, &fact_ids) {
        return Err("send_facts_on_connection key does not match payload".to_string());
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

fn push_id(out: &mut Vec<u8>, id: &HandlerId) {
    out.extend_from_slice(id);
}

fn push_ids(out: &mut Vec<u8>, values: &[HandlerId]) {
    out.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for value in values {
        push_id(out, value);
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn id(&mut self) -> Result<HandlerId, String> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn ids(&mut self) -> Result<Vec<HandlerId>, String> {
        let len = self.u32()? as usize;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(self.id()?);
        }
        Ok(values)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
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

#[derive(Debug, Clone, Default)]
pub struct SendFactsOnConnectionHandler;

impl SendFactsOnConnectionHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SendFactsOnConnectionHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == SEND_FACTS_ON_CONNECTION
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_send_facts_on_connection(intent)?;
        let mut ids = Vec::with_capacity(1 + input.fact_ids.len());
        ids.push(input.connection_id);
        ids.extend(input.fact_ids);
        Ok(ids)
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_send_facts_on_connection(intent)?;
        let connection_fact = context.require_fact(&input.connection_id)?;
        let connection = response::layout::decode_fact(&connection_fact.bytes)?;
        if connection_fact.id != input.connection_id {
            return Err("send_facts_on_connection connection fact id mismatch".to_string());
        }

        let mut facts = TransitFactBundle::new();
        for fact_id in &input.fact_ids {
            let fact = context.require_fact(fact_id)?;
            facts.push(create::require_sendable_fact(fact)?.to_vec());
        }

        let local_endpoint = endpoint::local_endpoint::local_endpoint(context.store()?)?
            .ok_or_else(|| "send_facts_on_connection requires local endpoint state".to_string())?;
        let (sender_endpoint, receiver_endpoint) =
            if local_endpoint.endpoint == connection.from_endpoint {
                (connection.from_endpoint, connection.to_endpoint)
            } else if local_endpoint.endpoint == connection.to_endpoint {
                (connection.to_endpoint, connection.from_endpoint)
            } else {
                return Err(
                    "send_facts_on_connection local endpoint is not part of connection".to_string(),
                );
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
            HandlerOutput::new().intent(send_network_frame::send_network_frame_intent(
                SendNetworkFrame {
                    routing_key: input.connection_id,
                    frame,
                },
            )),
        )
    }
}
