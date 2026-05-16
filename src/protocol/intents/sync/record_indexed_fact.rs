//! Sync indexed-fact recording intent layout.
//!
//! `record_indexed_fact` records that an applied shared fact has been
//! observed by the local store so future summaries can derive from the
//! durable fact set. The handler is intentionally bounded: it consumes the
//! update only after the referenced non-local fact is present with the
//! expected timestamp.

use crate::core::intents::{Intent, IntentExecution, IntentKind};

pub const RECORD_INDEXED_FACT: &str = "record_indexed_fact";

pub type HandlerId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordIndexedFact {
    pub fact_id: HandlerId,
    pub timestamp_ms: u64,
}

pub fn record_indexed_fact_intent(input: RecordIndexedFact) -> Intent {
    let mut payload = Vec::with_capacity(1 + 32 + 8);
    payload.push(1);
    payload.extend_from_slice(&input.fact_id);
    payload.extend_from_slice(&input.timestamp_ms.to_be_bytes());
    Intent::new(
        IntentKind::new(RECORD_INDEXED_FACT).expect("valid record_indexed_fact kind"),
        IntentExecution::Deferred,
        record_indexed_fact_key(&input),
        payload,
    )
}

pub fn decode_record_indexed_fact(intent: &Intent) -> Result<RecordIndexedFact, String> {
    if intent.kind.as_str() != RECORD_INDEXED_FACT {
        return Err("expected record_indexed_fact intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("record_indexed_fact intent must be deferred".to_string());
    }
    let mut reader = Reader::new(&intent.payload);
    if reader.u8()? != 1 {
        return Err("record_indexed_fact payload version unsupported".to_string());
    }
    let fact_id = reader.id()?;
    let timestamp_ms = reader.u64()?;
    reader.finish()?;
    let input = RecordIndexedFact {
        fact_id,
        timestamp_ms,
    };
    if intent.key != record_indexed_fact_key(&input) {
        return Err("record_indexed_fact idempotence key does not match payload".to_string());
    }
    Ok(input)
}

fn record_indexed_fact_key(input: &RecordIndexedFact) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync-index-update:record:v1:");
    hash.update(&input.fact_id);
    hash.update(&input.timestamp_ms.to_be_bytes());
    hash.finalize().as_bytes().to_vec()
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn u8(&mut self) -> Result<u8, String> {
        let byte = self.take(1)?;
        Ok(byte[0])
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn id(&mut self) -> Result<[u8; 32], String> {
        let bytes = self.take(32)?;
        Ok(bytes.try_into().unwrap())
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

// Handler for sync fact observation.
//
// The target path treats the fact table as the durable source of fact
// presence. This handler therefore declares the exact fact it needs,
// verifies it is available and non-local, and then consumes the deferred
// update. It does not own a process-wide index or scan unrelated rows.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};

#[derive(Debug, Clone, Default)]
pub struct RecordIndexedFactHandler;

impl RecordIndexedFactHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for RecordIndexedFactHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == RECORD_INDEXED_FACT
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_record_indexed_fact(intent)?;
        Ok(vec![input.fact_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_record_indexed_fact(raw)?;
        let fact = context.require_fact(&input.fact_id)?;
        context.require_non_local_fact_bytes(&input.fact_id)?;
        if fact.timestamp != input.timestamp_ms {
            return Err("record_indexed_fact timestamp does not match fact".to_string());
        }
        Ok(HandlerOutput::new())
    }
}
