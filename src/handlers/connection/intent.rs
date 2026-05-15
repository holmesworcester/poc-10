//! Connection intent layouts.
//!
//! Connection handlers own route selection, transport send/drain bookkeeping,
//! and send acknowledgement. They do not own transit cryptographic packaging
//! and must treat transit frames as opaque bytes.

use crate::core::intents::{Intent, IntentExecution, IntentKind};

pub const CONNECTION_SEND_FRAME: &str = "connection_send_frame";
pub const CONNECTION_MARK_SENT: &str = "connection_mark_sent";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionSendFrame {
    pub target_addr: String,
    pub transit_out_keys: Vec<Vec<u8>>,
    pub frame: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionMarkSent {
    pub transit_out_keys: Vec<Vec<u8>>,
}

pub fn send_frame_intent(input: ConnectionSendFrame) -> Intent {
    let mut payload = Vec::new();
    push_bytes(&mut payload, input.target_addr.as_bytes());
    push_vecs(&mut payload, &input.transit_out_keys);
    push_bytes(&mut payload, &input.frame);

    Intent::new(
        IntentKind::new(CONNECTION_SEND_FRAME).expect("valid connection send frame intent kind"),
        IntentExecution::Deferred,
        input.target_addr.into_bytes(),
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
    let transit_out_keys = reader.vecs()?;
    let frame = reader.bytes()?.to_vec();
    reader.finish()?;

    if intent.key != target_addr.as_bytes() {
        return Err("connection send idempotence key must be the target address".to_string());
    }

    Ok(ConnectionSendFrame {
        target_addr,
        transit_out_keys,
        frame,
    })
}

pub fn mark_sent_intent(input: ConnectionMarkSent) -> Intent {
    let mut payload = Vec::new();
    push_vecs(&mut payload, &input.transit_out_keys);

    Intent::new(
        IntentKind::new(CONNECTION_MARK_SENT).expect("valid connection mark sent intent kind"),
        IntentExecution::Deferred,
        b"transit_out".to_vec(),
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
    let transit_out_keys = reader.vecs()?;
    reader.finish()?;

    Ok(ConnectionMarkSent { transit_out_keys })
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
