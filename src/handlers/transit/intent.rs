//! Transit intent layouts.
//!
//! Transit handlers own cryptographic packaging and unwrapping of opaque transit
//! frames. They do not own connection transport, network IO, route cursors, or
//! event-module projection rows.

use crate::core::intents::{Intent, IntentExecution, IntentKind};

pub type HandlerId = [u8; 32];

pub const TRANSIT_WRAP_CONNECTION_BATCH: &str = "transit_wrap_connection_batch";
pub const TRANSIT_SEND_ON_CONNECTION: &str = "send_on_connection";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitWrapConnectionBatch {
    pub connection_id: HandlerId,
    pub sender_endpoint: HandlerId,
    pub recipient_endpoint: HandlerId,
    /// Names the connection secret dependency to load. The secret material is
    /// intentionally not embedded in the intent payload.
    pub connection_secret_id: HandlerId,
    /// Deterministic send item keys represented by this batch. Connection send
    /// handlers mark these only after network send succeeds.
    pub send_item_keys: Vec<Vec<u8>>,
    /// Canonical event bytes to be wrapped. Transit may inspect these only as
    /// plaintext inputs to packaging; connection transport receives only the
    /// resulting opaque frame.
    pub canonical_events: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitSendOnConnection {
    pub connection_id: HandlerId,
    pub event_id: HandlerId,
}

pub fn wrap_connection_batch_intent(input: TransitWrapConnectionBatch) -> Intent {
    let mut payload = Vec::new();
    push_id(&mut payload, &input.connection_id);
    push_id(&mut payload, &input.sender_endpoint);
    push_id(&mut payload, &input.recipient_endpoint);
    push_id(&mut payload, &input.connection_secret_id);
    push_vecs(&mut payload, &input.send_item_keys);
    push_vecs(&mut payload, &input.canonical_events);

    Intent::new(
        IntentKind::new(TRANSIT_WRAP_CONNECTION_BATCH)
            .expect("valid transit wrap connection batch intent kind"),
        IntentExecution::Deferred,
        input.connection_id,
        payload,
    )
}

pub fn decode_wrap_connection_batch(intent: &Intent) -> Result<TransitWrapConnectionBatch, String> {
    if intent.kind.as_str() != TRANSIT_WRAP_CONNECTION_BATCH {
        return Err("expected transit_wrap_connection_batch intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("transit wrap intent must be deferred".to_string());
    }

    let mut reader = Reader::new(&intent.payload);
    let connection_id = reader.id()?;
    let sender_endpoint = reader.id()?;
    let recipient_endpoint = reader.id()?;
    let connection_secret_id = reader.id()?;
    let send_item_keys = reader.vecs()?;
    let canonical_events = reader.vecs()?;
    reader.finish()?;

    if intent.key != connection_id {
        return Err("transit wrap idempotence key must be the connection id".to_string());
    }

    Ok(TransitWrapConnectionBatch {
        connection_id,
        sender_endpoint,
        recipient_endpoint,
        connection_secret_id,
        send_item_keys,
        canonical_events,
    })
}

pub fn send_on_connection_intent(input: TransitSendOnConnection) -> Intent {
    let mut payload = Vec::with_capacity(65);
    payload.push(1);
    push_id(&mut payload, &input.connection_id);
    push_id(&mut payload, &input.event_id);

    Intent::new(
        IntentKind::new(TRANSIT_SEND_ON_CONNECTION).expect("valid transit send intent kind"),
        IntentExecution::Deferred,
        connection_event_key(input.connection_id, input.event_id),
        payload,
    )
}

pub fn decode_send_on_connection(intent: &Intent) -> Result<TransitSendOnConnection, String> {
    if intent.kind.as_str() != TRANSIT_SEND_ON_CONNECTION {
        return Err("expected send_on_connection intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("send_on_connection intent must be deferred".to_string());
    }
    if intent.payload.len() != 65 || intent.payload[0] != 1 {
        return Err("send_on_connection payload is malformed".to_string());
    }
    let connection_id = intent.payload[1..33].try_into().unwrap();
    let event_id = intent.payload[33..65].try_into().unwrap();
    if intent.key != connection_event_key(connection_id, event_id) {
        return Err("send_on_connection key does not match payload".to_string());
    }
    Ok(TransitSendOnConnection {
        connection_id,
        event_id,
    })
}

fn connection_event_key(connection_id: HandlerId, event_id: HandlerId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&connection_id);
    key.extend_from_slice(&event_id);
    key
}

fn push_id(out: &mut Vec<u8>, id: &HandlerId) {
    out.extend_from_slice(id);
}

fn push_vecs(out: &mut Vec<u8>, values: &[Vec<u8>]) {
    out.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for value in values {
        push_bytes(out, value);
    }
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

    fn id(&mut self) -> Result<HandlerId, String> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn vecs(&mut self) -> Result<Vec<Vec<u8>>, String> {
        let len = self.u32()? as usize;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(self.bytes()?.to_vec());
        }
        Ok(values)
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        self.take(len)
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
