//! Sync inbound handler intent layouts.
//!
//! `handle_sync` owns the inbound sync decision step: a connection has
//! delivered an event payload referencing a parent/dependency the local
//! store may or may not have. The handler decides whether to ask for a
//! missing dependency by emitting a follow-up `sync_need_id` intent.
//!
//! This file only encodes payload bytes and idempotence keys. Durable event
//! presence is provided through the handler fact context.

use crate::core::intents::{Intent, IntentExecution, IntentKind};

pub const PROCESS_SYNC_INBOUND: &str = "process_sync_inbound";
pub const SYNC_NEED_ID: &str = "sync_need_id";
pub const RESPOND_TO_SYNC_COMPARE: &str = "respond_to_sync_compare";
pub const REQUEST_SYNC_ID: &str = "request_sync_id";
pub const RESPOND_TO_SYNC_NEED: &str = "respond_to_sync_need";

pub type HandlerId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSyncInbound {
    pub connection_id: HandlerId,
    pub event_id: HandlerId,
    /// Optional dependency reported missing for the inbound event. The handler
    /// re-checks the fact context before emitting a `sync_need_id` follow-up.
    pub missing_dep_id: Option<HandlerId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncNeedId {
    pub connection_id: HandlerId,
    pub needed_id: HandlerId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespondToSyncCompare {
    pub compare_fact_id: HandlerId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSyncId {
    pub have_fact_id: HandlerId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespondToSyncNeed {
    pub need_fact_id: HandlerId,
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
        _ => return Err("process_sync_inbound dependency tag invalid".to_string()),
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

pub fn respond_to_sync_compare_intent(input: RespondToSyncCompare) -> Intent {
    let mut payload = Vec::with_capacity(1 + 32);
    payload.push(1);
    payload.extend_from_slice(&input.compare_fact_id);
    Intent::new(
        IntentKind::new(RESPOND_TO_SYNC_COMPARE).expect("valid respond_to_sync_compare kind"),
        IntentExecution::Deferred,
        respond_to_sync_compare_key(&input),
        payload,
    )
}

pub fn request_sync_id_intent(input: RequestSyncId) -> Intent {
    let mut payload = Vec::with_capacity(1 + 32);
    payload.push(1);
    payload.extend_from_slice(&input.have_fact_id);
    Intent::new(
        IntentKind::new(REQUEST_SYNC_ID).expect("valid request_sync_id kind"),
        IntentExecution::Deferred,
        request_sync_id_key(&input),
        payload,
    )
}

pub fn decode_request_sync_id(intent: &Intent) -> Result<RequestSyncId, String> {
    if intent.kind.as_str() != REQUEST_SYNC_ID {
        return Err("expected request_sync_id intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("request_sync_id intent must be deferred".to_string());
    }
    let mut reader = Reader::new(&intent.payload);
    if reader.u8()? != 1 {
        return Err("request_sync_id payload version unsupported".to_string());
    }
    let have_fact_id = reader.id()?;
    reader.finish()?;
    let input = RequestSyncId { have_fact_id };
    if intent.key != request_sync_id_key(&input) {
        return Err("request_sync_id idempotence key does not match payload".to_string());
    }
    Ok(input)
}

pub fn respond_to_sync_need_intent(input: RespondToSyncNeed) -> Intent {
    let mut payload = Vec::with_capacity(1 + 32);
    payload.push(1);
    payload.extend_from_slice(&input.need_fact_id);
    Intent::new(
        IntentKind::new(RESPOND_TO_SYNC_NEED).expect("valid respond_to_sync_need kind"),
        IntentExecution::Deferred,
        respond_to_sync_need_key(&input),
        payload,
    )
}

pub fn decode_respond_to_sync_need(intent: &Intent) -> Result<RespondToSyncNeed, String> {
    if intent.kind.as_str() != RESPOND_TO_SYNC_NEED {
        return Err("expected respond_to_sync_need intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("respond_to_sync_need intent must be deferred".to_string());
    }
    let mut reader = Reader::new(&intent.payload);
    if reader.u8()? != 1 {
        return Err("respond_to_sync_need payload version unsupported".to_string());
    }
    let need_fact_id = reader.id()?;
    reader.finish()?;
    let input = RespondToSyncNeed { need_fact_id };
    if intent.key != respond_to_sync_need_key(&input) {
        return Err("respond_to_sync_need idempotence key does not match payload".to_string());
    }
    Ok(input)
}

pub fn decode_respond_to_sync_compare(intent: &Intent) -> Result<RespondToSyncCompare, String> {
    if intent.kind.as_str() != RESPOND_TO_SYNC_COMPARE {
        return Err("expected respond_to_sync_compare intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("respond_to_sync_compare intent must be deferred".to_string());
    }
    let mut reader = Reader::new(&intent.payload);
    if reader.u8()? != 1 {
        return Err("respond_to_sync_compare payload version unsupported".to_string());
    }
    let compare_fact_id = reader.id()?;
    reader.finish()?;
    let input = RespondToSyncCompare { compare_fact_id };
    if intent.key != respond_to_sync_compare_key(&input) {
        return Err("respond_to_sync_compare idempotence key does not match payload".to_string());
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

fn respond_to_sync_compare_key(input: &RespondToSyncCompare) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync:respond-to-compare:v1:");
    hash.update(&input.compare_fact_id);
    hash.finalize().as_bytes().to_vec()
}

fn request_sync_id_key(input: &RequestSyncId) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync:request-id:v1:");
    hash.update(&input.have_fact_id);
    hash.finalize().as_bytes().to_vec()
}

fn respond_to_sync_need_key(input: &RespondToSyncNeed) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync:respond-to-need:v1:");
    hash.update(&input.need_fact_id);
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
// Real but minimal: this handler implements the bounded inbound dependency
// decision. The inbound event fact must be present; an optional dependency is
// checked through the same fact context, and a missing dependency emits one
// deterministic `sync_need_id` follow-up.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::protocol::fact_modules::{sync_have_id, sync_need_id};
use crate::protocol::intent_handlers::transit::{
    send_on_connection_intent, TransitSendOnConnection,
};

#[derive(Debug, Clone, Default)]
pub struct HandleSyncHandler;

impl HandleSyncHandler {
    pub fn new() -> Self {
        Self
    }
}

// Handler for sync have-id follow-up.
//
// A `sync_have_id` fact says a peer has a concrete event id. If the local store
// lacks that id, this handler creates and sends the deterministic
// `sync_need_id` fact for the same connection. The presence check is stateful
// and exact, so it belongs in this bounded handler rather than in the
// have-id projector.

#[derive(Debug, Clone, Default)]
pub struct RequestSyncIdHandler;

impl RequestSyncIdHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for RequestSyncIdHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == REQUEST_SYNC_ID
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_request_sync_id(intent)?;
        Ok(vec![input.have_fact_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_request_sync_id(raw)?;
        let have_fact = context.require_fact(&input.have_fact_id)?;
        let have = sync_have_id::layout::decode_fact(&have_fact.bytes)?;
        if crate::core::wake_loop::persisted_fact(context.store()?, &have.event_id)?.is_some() {
            return Ok(HandlerOutput::new());
        }
        let need = sync_need_id::fact::SyncNeedIdFact {
            connection_id: have.connection_id,
            event_id: have.event_id,
        };
        let need_fact = sync_need_id::create::fact(need, have_fact.timestamp)?;
        Ok(HandlerOutput::new()
            .fact(need_fact.clone())
            .intent(send_on_connection_intent(TransitSendOnConnection {
                connection_id: have.connection_id,
                fact_ids: vec![need_fact.id],
            })))
    }
}

// Handler for sync need-id answers.
//
// A `sync_need_id` fact is a deterministic request for one event id. If this
// store has the event and transit allows it to be sent, the handler emits the
// normal send-on-connection intent for that fact id.

#[derive(Debug, Clone, Default)]
pub struct RespondToSyncNeedHandler;

impl RespondToSyncNeedHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for RespondToSyncNeedHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == RESPOND_TO_SYNC_NEED
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_respond_to_sync_need(intent)?;
        Ok(vec![input.need_fact_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_respond_to_sync_need(raw)?;
        let need_fact = context.require_fact(&input.need_fact_id)?;
        let need = sync_need_id::layout::decode_fact(&need_fact.bytes)?;
        let Some(fact) = crate::core::wake_loop::persisted_fact(context.store()?, &need.event_id)?
        else {
            return Ok(HandlerOutput::new());
        };
        crate::protocol::fact_modules::transit::create::require_sendable_fact(&fact)?;
        Ok(
            HandlerOutput::new().intent(send_on_connection_intent(TransitSendOnConnection {
                connection_id: need.connection_id,
                fact_ids: vec![need.event_id],
            })),
        )
    }
}

impl IntentHandler for HandleSyncHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == PROCESS_SYNC_INBOUND
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_process_sync_inbound(intent)?;
        let mut ids = vec![input.event_id];
        if let Some(dependency_id) = input.missing_dep_id {
            ids.push(dependency_id);
        }
        Ok(ids)
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_process_sync_inbound(raw)?;
        context.require_fact(&input.event_id)?;
        match input.missing_dep_id {
            None => Ok(HandlerOutput::new()),
            Some(needed_id) => {
                if context.fact(&needed_id).is_some() {
                    return Ok(HandlerOutput::new());
                }
                let follow_up = sync_need_id_intent(SyncNeedId {
                    connection_id: input.connection_id,
                    needed_id,
                });
                Ok(HandlerOutput::new().intent(follow_up))
            }
        }
    }
}

// Handler for sync compare responses.
//
// The intent names the exact compare fact to answer. Core supplies the durable
// fact context; this handler then filters that context to the compare's bounded
// timestamp range, computes the local summary, emits a response compare, and
// advertises local ids when the peer's summary differs.

#[derive(Debug, Clone, Default)]
pub struct RespondToSyncCompareHandler;

impl RespondToSyncCompareHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for RespondToSyncCompareHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == RESPOND_TO_SYNC_COMPARE
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_respond_to_sync_compare(intent)?;
        Ok(vec![input.compare_fact_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_respond_to_sync_compare(raw)?;
        let compare_fact = context.require_fact(&input.compare_fact_id)?;
        let compare =
            crate::protocol::fact_modules::sync_compare::layout::decode_fact(&compare_fact.bytes)?;
        let available_facts = match context.store() {
            Ok(store) => crate::core::wake_loop::persisted_facts(store)?,
            Err(_) => context.facts().cloned().collect(),
        };
        let mut output = HandlerOutput::new();
        let response_facts = crate::protocol::fact_modules::sync_compare::create::response_facts(
            compare_fact,
            available_facts.iter(),
        )?;
        let fact_ids = response_facts
            .iter()
            .map(|fact| fact.id)
            .collect::<Vec<_>>();
        for fact in response_facts {
            output = output.fact(fact);
        }
        if !fact_ids.is_empty() {
            output = output.intent(send_on_connection_intent(TransitSendOnConnection {
                connection_id: compare.connection_id,
                fact_ids,
            }));
        }
        Ok(output)
    }
}
