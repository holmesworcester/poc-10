//! Connection intent layouts.
//!
//! Connection handlers own route selection, transport send/drain bookkeeping,
//! and send acknowledgement. They do not own transit cryptographic packaging
//! and must treat transit frames as opaque bytes.

use crate::core::intents::{Intent, IntentExecution, IntentKind};

pub const CONNECTION_SEND_FRAME: &str = "connection_send_frame";
pub const CONNECTION_MARK_SENT: &str = "connection_mark_sent";
pub const CONNECTION_SEND_REQUEST: &str = "connection_send_request";
pub const CONNECTION_SEND_RESPONSE: &str = "connection_send_response";

pub type HandlerId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionSendFrame {
    pub target_addr: String,
    pub send_item_keys: Vec<Vec<u8>>,
    pub frame: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionMarkSent {
    pub send_item_keys: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionSendRequest {
    pub request_id: HandlerId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionSendResponse {
    pub request_id: HandlerId,
}

pub fn send_frame_intent(input: ConnectionSendFrame) -> Intent {
    let mut payload = Vec::new();
    push_bytes(&mut payload, input.target_addr.as_bytes());
    push_vecs(&mut payload, &input.send_item_keys);
    push_bytes(&mut payload, &input.frame);

    Intent::new(
        IntentKind::new(CONNECTION_SEND_FRAME).expect("valid connection send frame intent kind"),
        IntentExecution::Deferred,
        send_frame_key(&input),
        payload,
    )
}

pub fn decode_send_frame(intent: &Intent) -> Result<ConnectionSendFrame, String> {
    if intent.kind.as_str() != CONNECTION_SEND_FRAME {
        return Err("expected connection_send_frame intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("connection send intent must be deferred".to_string());
    }

    let mut reader = Reader::new(&intent.payload);
    let target_addr = String::from_utf8(reader.bytes()?.to_vec())
        .map_err(|_| "connection send target must be utf8".to_string())?;
    let send_item_keys = reader.vecs()?;
    let frame = reader.bytes()?.to_vec();
    reader.finish()?;

    let input = ConnectionSendFrame {
        target_addr,
        send_item_keys,
        frame,
    };
    if intent.key != send_frame_key(&input) {
        return Err("connection send idempotence key does not match payload".to_string());
    }

    Ok(input)
}

pub fn mark_sent_intent(input: ConnectionMarkSent) -> Intent {
    let mut payload = Vec::new();
    push_vecs(&mut payload, &input.send_item_keys);

    Intent::new(
        IntentKind::new(CONNECTION_MARK_SENT).expect("valid connection mark sent intent kind"),
        IntentExecution::Deferred,
        mark_sent_key(&input),
        payload,
    )
}

pub fn decode_mark_sent(intent: &Intent) -> Result<ConnectionMarkSent, String> {
    if intent.kind.as_str() != CONNECTION_MARK_SENT {
        return Err("expected connection_mark_sent intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("connection mark sent intent must be deferred".to_string());
    }

    let mut reader = Reader::new(&intent.payload);
    let send_item_keys = reader.vecs()?;
    reader.finish()?;

    let input = ConnectionMarkSent { send_item_keys };
    if intent.key != mark_sent_key(&input) {
        return Err("connection mark-sent idempotence key does not match payload".to_string());
    }

    Ok(input)
}

pub fn send_request_intent(input: ConnectionSendRequest) -> Intent {
    single_id_intent(CONNECTION_SEND_REQUEST, input.request_id)
}

pub fn decode_send_request(intent: &Intent) -> Result<ConnectionSendRequest, String> {
    Ok(ConnectionSendRequest {
        request_id: decode_single_id(intent, CONNECTION_SEND_REQUEST)?,
    })
}

pub fn send_response_intent(input: ConnectionSendResponse) -> Intent {
    single_id_intent(CONNECTION_SEND_RESPONSE, input.request_id)
}

pub fn decode_send_response(intent: &Intent) -> Result<ConnectionSendResponse, String> {
    Ok(ConnectionSendResponse {
        request_id: decode_single_id(intent, CONNECTION_SEND_RESPONSE)?,
    })
}

fn single_id_intent(kind: &str, id: HandlerId) -> Intent {
    let mut payload = Vec::with_capacity(33);
    payload.push(1);
    payload.extend_from_slice(&id);
    Intent::new(
        IntentKind::new(kind).expect("valid connection intent kind"),
        IntentExecution::Deferred,
        id,
        payload,
    )
}

fn decode_single_id(intent: &Intent, expected_kind: &str) -> Result<HandlerId, String> {
    if intent.kind.as_str() != expected_kind {
        return Err(format!("expected {expected_kind} intent"));
    }
    if intent.execution != IntentExecution::Deferred {
        return Err(format!("{expected_kind} intent must be deferred"));
    }
    if intent.payload.len() != 33 || intent.payload[0] != 1 {
        return Err(format!("{expected_kind} payload is malformed"));
    }
    let id = intent.payload[1..33].try_into().unwrap();
    if intent.key != id {
        return Err(format!(
            "{expected_kind} idempotence key does not match payload"
        ));
    }
    Ok(id)
}

fn send_frame_key(input: &ConnectionSendFrame) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:connection-send-frame:v1:");
    hash.update(input.target_addr.as_bytes());
    hash_vecs(&mut hash, &input.send_item_keys);
    hash.update(&(input.frame.len() as u32).to_be_bytes());
    hash.update(&input.frame);
    hash.finalize().as_bytes().to_vec()
}

fn mark_sent_key(input: &ConnectionMarkSent) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:connection-mark-sent:v1:");
    hash_vecs(&mut hash, &input.send_item_keys);
    hash.finalize().as_bytes().to_vec()
}

fn hash_vecs(hash: &mut blake3::Hasher, values: &[Vec<u8>]) {
    hash.update(&(values.len() as u32).to_be_bytes());
    for value in values {
        hash.update(&(value.len() as u32).to_be_bytes());
        hash.update(value);
    }
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
