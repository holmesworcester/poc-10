//! Sync inbound handler intent layouts.
//!
//! `handle_sync` owns the inbound sync decision step: a connection has
//! delivered an event payload referencing a parent/dependency the local
//! store may or may not have. The handler decides whether to ask for a
//! missing dependency by emitting a follow-up `sync_need_id` intent.
//!
//! This file only encodes payload bytes and idempotence keys; legacy
//! `SyncIndex` mutation lives in `src/legacy/workers/sync.rs` until Wave 6.

use crate::core::intents::{Intent, IntentExecution, IntentKind};

pub const PROCESS_SYNC_INBOUND: &str = "process_sync_inbound";
pub const SYNC_NEED_ID: &str = "sync_need_id";

pub type HandlerId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSyncInbound {
    pub connection_id: HandlerId,
    pub event_id: HandlerId,
    /// When present, the connection has delivered an event that depends on
    /// a fact id the local store has not yet materialized; the handler will
    /// emit a `sync_need_id` follow-up.
    pub missing_dep_id: Option<HandlerId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncNeedId {
    pub connection_id: HandlerId,
    pub needed_id: HandlerId,
}

pub fn process_sync_inbound_intent(input: ProcessSyncInbound) -> Intent {
    let mut payload = Vec::with_capacity(1 + 32 + 32 + 1 + 32);
    payload.push(1);
    payload.extend_from_slice(&input.connection_id);
    payload.extend_from_slice(&input.event_id);
    match input.missing_dep_id {
        None => payload.push(0),
        Some(dep) => {
            payload.push(1);
            payload.extend_from_slice(&dep);
        }
    }
    Intent::new(
        IntentKind::new(PROCESS_SYNC_INBOUND).expect("valid process_sync_inbound kind"),
        IntentExecution::Deferred,
        process_sync_inbound_key(&input),
        payload,
    )
}

pub fn decode_process_sync_inbound(intent: &Intent) -> Result<ProcessSyncInbound, String> {
    if intent.kind.as_str() != PROCESS_SYNC_INBOUND {
        return Err("expected process_sync_inbound intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("process_sync_inbound intent must be deferred".to_string());
    }
    let mut reader = Reader::new(&intent.payload);
    if reader.u8()? != 1 {
        return Err("process_sync_inbound payload version unsupported".to_string());
    }
    let connection_id = reader.id()?;
    let event_id = reader.id()?;
    let missing_dep_id = match reader.u8()? {
        0 => None,
        1 => Some(reader.id()?),
        _ => return Err("process_sync_inbound missing_dep tag invalid".to_string()),
    };
    reader.finish()?;
    let input = ProcessSyncInbound {
        connection_id,
        event_id,
        missing_dep_id,
    };
    if intent.key != process_sync_inbound_key(&input) {
        return Err("process_sync_inbound idempotence key does not match payload".to_string());
    }
    Ok(input)
}

pub fn sync_need_id_intent(input: SyncNeedId) -> Intent {
    let mut payload = Vec::with_capacity(1 + 32 + 32);
    payload.push(1);
    payload.extend_from_slice(&input.connection_id);
    payload.extend_from_slice(&input.needed_id);
    Intent::new(
        IntentKind::new(SYNC_NEED_ID).expect("valid sync_need_id kind"),
        IntentExecution::Deferred,
        sync_need_id_key(&input),
        payload,
    )
}

pub fn decode_sync_need_id(intent: &Intent) -> Result<SyncNeedId, String> {
    if intent.kind.as_str() != SYNC_NEED_ID {
        return Err("expected sync_need_id intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("sync_need_id intent must be deferred".to_string());
    }
    let mut reader = Reader::new(&intent.payload);
    if reader.u8()? != 1 {
        return Err("sync_need_id payload version unsupported".to_string());
    }
    let connection_id = reader.id()?;
    let needed_id = reader.id()?;
    reader.finish()?;
    let input = SyncNeedId {
        connection_id,
        needed_id,
    };
    if intent.key != sync_need_id_key(&input) {
        return Err("sync_need_id idempotence key does not match payload".to_string());
    }
    Ok(input)
}

fn process_sync_inbound_key(input: &ProcessSyncInbound) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:handle-sync:process-inbound:v1:");
    hash.update(&input.connection_id);
    hash.update(&input.event_id);
    match input.missing_dep_id {
        None => hash.update(&[0]),
        Some(dep) => {
            hash.update(&[1]);
            hash.update(&dep)
        }
    };
    hash.finalize().as_bytes().to_vec()
}

fn sync_need_id_key(input: &SyncNeedId) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:handle-sync:need-id:v1:");
    hash.update(&input.connection_id);
    hash.update(&input.needed_id);
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

// Handler for inbound sync decisions.
//
// Real but minimal: this handler implements one sync decision path — when
// an inbound event references a dependency the local store has not yet
// materialized, emit a `sync_need_id` follow-up. Full
// `drain_sync_works`/`StoreSyncContext` mutable-index logic stays in
// `src/legacy/workers/sync.rs` until Wave 6 retires the legacy worker.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};

#[derive(Debug, Clone, Default)]
pub struct HandleSyncHandler;

impl HandleSyncHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for HandleSyncHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == PROCESS_SYNC_INBOUND
    }

    fn input_fact_ids(&self, _intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        // The minimal decision path inspects only the intent payload itself;
        // when wave 6 lifts `StoreSyncContext` into facts, the relevant
        // workspace + connection fact ids will be declared here.
        Ok(Vec::new())
    }

    fn handle(&self, raw: &Intent, _context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_process_sync_inbound(raw)?;
        match input.missing_dep_id {
            None => Ok(HandlerOutput::new()),
            Some(needed_id) => {
                let follow_up = sync_need_id_intent(SyncNeedId {
                    connection_id: input.connection_id,
                    needed_id,
                });
                Ok(HandlerOutput::new().intent(follow_up))
            }
        }
    }
}
