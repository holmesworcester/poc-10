//! Receive-transit intent layout.
//!
//! Receive-transit handlers own decoding an inbound transit frame, verifying
//! the public envelope, and emitting the recovered inner fact for admission.
//! The intent payload carries only the opaque outer frame bytes; cryptographic
//! material is loaded by the driver from the fact context.

use crate::core::intents::{Intent, IntentExecution, IntentKind};

pub const RECEIVE_TRANSIT_FRAME: &str = "receive_transit_frame";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveTransitFrame {
    /// Raw outer transit frame bytes as received from the network. The driver
    /// peeks the public header and dispatches to the matching size class.
    pub frame: Vec<u8>,
}

pub fn receive_transit_frame_intent(input: ReceiveTransitFrame) -> Intent {
    let mut payload = Vec::with_capacity(4 + input.frame.len());
    push_bytes(&mut payload, &input.frame);
    Intent::new(
        IntentKind::new(RECEIVE_TRANSIT_FRAME).expect("valid receive transit intent kind"),
        IntentExecution::Deferred,
        receive_transit_key(&input),
        payload,
    )
}

pub fn decode_receive_transit_frame(intent: &Intent) -> Result<ReceiveTransitFrame, String> {
    if intent.kind.as_str() != RECEIVE_TRANSIT_FRAME {
        return Err("expected receive_transit_frame intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("receive transit intent must be deferred".to_string());
    }

    let mut reader = Reader::new(&intent.payload);
    let frame = reader.bytes()?.to_vec();
    reader.finish()?;

    let input = ReceiveTransitFrame { frame };
    if intent.key != receive_transit_key(&input) {
        return Err("receive transit idempotence key does not match payload".to_string());
    }
    Ok(input)
}

fn receive_transit_key(input: &ReceiveTransitFrame) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:receive-transit-frame:v1:");
    hash.update(&(input.frame.len() as u32).to_be_bytes());
    hash.update(&input.frame);
    hash.finalize().as_bytes().to_vec()
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
